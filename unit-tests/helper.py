import sys
import re
import subprocess
import random
import netns
import json
import imp
import socket
import fcntl
import struct
import logging
import ipaddr

sys.path.append('../config')
#from ns_setup import *
from setup import ovs_class
from scapy.all import *

reload(sys)

sys.setdefaultencoding("utf-8")
conf.loglevel = 1

colorred = "\033[01;31m{0}\033[00m"
colorgrn = "\033[1;34m{0}\033[00m"
# BFD - Bidirectional Forwarding Detection - RFC 5880, 5881

# scapy.contrib.description = BFD
# scapy.contrib.status = loads

from scapy.packet import *
from scapy.fields import *
from scapy.all import * # Otherwise failing at the UDP reference below
CRED = '\033[91m'
CEND = '\033[0m'

class BFD(Packet):
    name = "BFD"
    fields_desc = [
                    BitField("version" , 1 , 3),
                    BitField("diag" , 0 , 5),
                    BitField("sta" , 3 , 2),
                    FlagsField("flags", 0x00, 6, ['P', 'F', 'C', 'A', 'D', 'M']),
                    XByteField("detect_mult", 0x03),
                    XByteField("len", 24),
                    BitField("my_discriminator" , 0x11111111 , 32),
                    BitField("your_discriminator" , 0x22222222 , 32),
                    BitField("min_tx_interval" , 1000000000, 32),
                    BitField("min_rx_interval" , 1000000000, 32),
                    BitField("echo_rx_interval" , 1000000000, 32) ]

    def mysummary(self):
        return self.sprintf("BFD (my_disc=%BFD.my_discriminator%, "\
                            "your_disc=%BFD.my_discriminator%)")

bind_layers(UDP, BFD, dport=3784)
bind_layers(UDP, BFD, dport=4784)
def randomMAC():
    mac = [ 0x00, 0x16, 0x3e,
        random.randint(0x00, 0x7f),
        random.randint(0x00, 0xff),
        random.randint(0x00, 0xff) ]
    return ':'.join(map(lambda x: "%02x" % x, mac))

def parse(tags, pattern, cmd):
    output = subprocess.check_output(cmd, shell=True)
    results = {}
    for tag in tags:
        match = re.search(r'^'+tag+pattern, output,  re.MULTILINE)
        m = match.group(0).split('\n')
        results[m[0]] = []
        for i in range(1, len(m)):
            results[m[0]].append(m[i].split()[0])
    return results

def parse_dhcp_pool_show(evpn_id):
    tags = ['Available IP addresses', 'Allocated IP addresses', 'Declined IP addresses']
    #pattern = '\n^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
    pattern = '(($(\n^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})((\t)+([0-9]+)*s)?)$)*'
    return parse(tags, pattern, 'ovs-appctl evpn/dhcp-pool-show alubr0 '+evpn_id)

def array_value_exits(array, v):
    for i in  array:
        if i == v:
           return True;
    return False;
def get_pid(name):
    return int(subprocess.check_output(["pidof",name]))

def getcmdoutput(cmd):
    p = subprocess.Popen(cmd.split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return p.communicate()[0]

def mac_to_lla (mac):
    mac_value = int(mac.replace(':',''), 16)
    high2 = mac_value >> 32 & 0xffff ^ 0x0200
    high1 = mac_value >> 24 & 0xff
    low1 = mac_value >> 16 & 0xff
    low2 = mac_value & 0xffff
    return 'fe80::{:04x}:{:02x}ff:fe{:02x}:{:04x}'.format(high2, high1, low1, low2)

def ipRange(start_ip, end_ip):
   start = list(map(int, start_ip.split(".")))
   end = list(map(int, end_ip.split(".")))
   temp = start
   ip_range = []

   ip_range.append(start_ip)
   while temp != end:
      start[3] += 1
      for i in (3, 2, 1):
         if temp[i] == 256:
            temp[i] = 0
            temp[i-1] += 1
      ip_range.append(".".join(map(str, temp)))

   return ip_range
def call_prog_as_is (cmd, wait_time=None) :
    import select
    proc = subprocess.Popen (cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
    read_set = [proc.stdout, proc.stderr]
    out = []
    err = []

    while read_set :
        timeout = True
        try:
            rlist, wlist, xlist = select.select (read_set, [], [], wait_time)
        except select.error  as ex:
            if (ex[0] == 4):
                continue
        if proc.stdout in rlist :
           timeout = False
           data = os.read (proc.stdout.fileno (), 1024)
           if data == "" :
              proc.stdout.close ()
              read_set.remove (proc.stdout)
           out.append (data)
        if proc.stderr in rlist :
            timeout = False
            data = os.read (proc.stderr.fileno (), 1024)
            if data == "" :
               proc.stderr.close ()
               read_set.remove (proc.stderr)
            err.append (data)
        if timeout :
            raise Exception ("timeout")

    proc.wait ()
    out = ''.join (out)
    err = ''.join (err)
    reply = (proc.returncode, out, err)

    return reply

def exe(cmd, ignoreError= False):
    logging.debug("%s" % cmd)
    r = call_prog_as_is(cmd)
    if r[0] is not 0 and not ignoreError:
       logging.warn(CRED+"Failed cmd: %s  %s" % (cmd, CEND))
       logging.warn(CRED+"rc: %s, out: %s, err: %s %s" % (r[0], r[1], r[2], CEND))
    return r
"""
def exe(cmd):
    logging.debug("%s" % cmd)
    FNULL = open(os.devnull, 'w')
    proc = subprocess.Popen(cmd, shell=True, stdout=FNULL, stderr=subprocess.STDOUT)
    #proc = subprocess.Popen(cmd, shell=True)
"""

class parent_test(object):
    #ovs = ovs_class('../config/config.json', 8 , 2)
    def setup_class(self):
        print('parent setup-class ...')
        self.ovs = ovs_class('../config/config.json', 8 , 2)
        self.ovs.readconfig()
        print self.ovs

    def teardown_class(self):
        pass

class NetworkUtil:
    @staticmethod
    def BFDResponder(iface, msg_count=1000):
        conf.iface = iface
        logging.info("BFDResponder")
        a = sniff(iface=conf.iface, timeout=10,
                  filter="udp and port 3784 or port 4784", count=1)
        for p in a:
            logging.info("BFD RCVD: %s" % p.command())
            dst_ip = p[IP].src
            src_ip = p[IP].dst
            dst_port = p[UDP].dport
            src_port = p[UDP].sport
            your_disc = int(p[BFD].my_discriminator)
        my_disc = random.randint(1, 2147483647)
        logging.info("BFD RSP: iface: %s, my_disc: %s, your_disc: 0x%x, "
                     "src_ip: %s,  dst_ip: %s" % (conf.iface, my_disc, your_disc,
                     src_ip, dst_ip))
        for i in [1, 2]:
            pkt = IP(src=src_ip, dst=dst_ip, proto=17, ttl=255)/UDP(sport=src_port,\
                     dport=dst_port)/BFD(version=1, your_discriminator=your_disc, \
                     my_discriminator=my_disc, min_tx_interval=1000000, \
                     min_rx_interval=1000000, echo_rx_interval=0, sta=i)
            logging.info("sending down/init %s ..." %pkt.command())
            send(pkt)
        pkt =  IP(src=src_ip, dst=dst_ip, proto=17, ttl=255)/UDP(sport=src_port,\
                  dport=dst_port)/BFD(version=1, your_discriminator=your_disc, \
                  my_discriminator=my_disc, min_tx_interval=1000000, \
                  min_rx_interval=1000000, echo_rx_interval=0, sta=3)
        logging.info("sending %s ..." % pkt.command())
        send(pkt, count=msg_count, inter=1)

    @staticmethod
    def getRandomIP(subnet, mask, ip6=False):
        nw = subnet +'/'+ mask
        if ip6:
           network = ipaddr.IPv6Network(nw)
           random_ip = ipaddr.IPv6Address(random.randrange(int(network.network) + 1,\
                            int(network.broadcast) - 1))
        else :
            network = ipaddr.IPv4Network(nw)
            random_ip = ipaddr.IPv4Address(random.randrange(int(network.network) + 1,\
                            int(network.broadcast) - 1))
        return random_ip
    @staticmethod
    def getHwAddr(ifname):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        info = fcntl.ioctl(s.fileno(), 0x8927,  struct.pack('256s', ifname[:15]))
        return ''.join(['%02x:' % ord(char) for char in info[18:24]])[:-1]
    @staticmethod
    def compose_arp_reply(src_ip, dst_ip, src_mac, dst_mac='ff:ff:ff:ff:ff:ff',
                          arp_op=2):
        pkt = Ether(src=src_mac, dst=dst_mac)/\
                   ARP(hwdst=dst_mac, psrc=src_ip, pdst=dst_ip,\
                   hwsrc=src_mac, op=arp_op)
        logging.debug("compose_arp: %s" % pkt.command())
        return pkt
    @staticmethod
    def compose_nd_pkt(src_mac, dst_mac, src_ip6, dst_ip6, nd_msg):
        pkt = Ether(dst=dst_mac, src=src_mac)/IPv6(src=src_ip6,dst=dst_ip6)
        if nd_msg == "solicit":
            pkt = pkt/ICMPv6ND_NS(tgt=dst_ip6)/\
                  ICMPv6NDOptSrcLLAddr(lladdr=src_mac)
        logging.debug("compose_nd: %s" % pkt.command())
        return pkt
    @staticmethod
    def send_grat_arp(ns, ip):
        #ns = "br2"
        #print "****learn_ip "+ip
        cnt = 0
        with netns.NetNS(nsname=ns):
             #subprocess.call(['ip', 'a'])
             #print conf
             conf.iface = ns+"-veth0"
             pkt = Ether(src='00:00:00:00:00:00', dst='ff:ff:ff:ff:ff:ff')/\
                   ARP(hwdst='ff:ff:ff:ff:ff:ff', psrc=ip, pdst=ip,\
                   hwsrc=randomMAC(), op=2)
             while(True):
                #print "\nsending ..."+str(cnt)
                sendp(pkt)
                time.sleep(1)
                cnt = cnt +1

    @staticmethod
    def get_conntrack():
        cmd = 'ip netns exec spat_ns conntrack -L -o xml'
        xml_output = subprocess.check_output(cmd, shell=True)
        root = ET.fromstring(xml_output)
        print root
        for flow in root.iter('flow'):
            for meta in flow.iter('meta'):
                for child in meta.iter('layer3'):
                    print child.tag, child.attrib
    @staticmethod
    def send_rcv(ns, pkt, cnt = 5, loop = True):
        ans = []
        with netns.NetNS(nsname=ns):
            #subprocess.call(['ip', 'a'])
            conf.verb=0
            conf.iface = ns+"-veth0"
            conf.iface6 = ns+"-veth0"
            logging.debug("%s, pkt: %s, cnt:%d" % (conf.iface, pkt.command(), cnt))
            if loop:
               ans, u = srploop(pkt, iface=conf.iface, timeout=5, count=cnt)
            else:
               ans, u = srp(pkt, iface=conf.iface, timeout=5)
        return ans

    @staticmethod
    def send_pkt_sniff(ns, pkt, cnt = 5, loop = True, sniff_filter= ''):
        ans = []
        if len(sniff_filter):
           logging.debug(sniff_filter)
        conf.verb=3
        with netns.NetNS(nsname=ns):
            #subprocess.call(['ip', 'a'])
            conf.iface = ns+"-veth0"
            conf.iface6 = ns+"-veth0"
            logging.debug("%s, pkt: %s, cnt:%d" % (conf.iface, pkt.command(), cnt))
            if loop:
               ans, u = srploop(pkt, iface=conf.iface, timeout=5,count=cnt)
               logging.debug(ans.summary())
               logging.debug(u.summary())
            else:
               sendp(pkt, iface=conf.iface)
               if len(sniff_filter):
                  ans=sniff(iface=conf.iface, timeout=5, filter=sniff_filter)
        return ans

    @staticmethod
    def send_icmp(source_ns, src_mac, dst_mac, src_ip, dst_ip, cnt = 5):
        pkt = Ether(src=src_mac, dst=dst_mac)\
              /IP(src=src_ip, dst=dst_ip)/ICMP(type=8, code=0,id=200)
        ans = NetworkUtil.send_pkt_sniff(source_ns, pkt, cnt)
        reply_count = 0
        for s, r in ans:
            code = r[ICMP].code
            src = r[IP].src
            dst = r[IP].dst
            if code != 0 or src != dst_ip or dst != src_ip:
               logging.error(colorred.format('Unexpected reply: (code: %s, '
                  'src: %s => dst: %s),'\
                  ' Expected: (code: %s, src: %s => dst: %s)'\
                  %(r[ICMP].code, r[IP].src, r[IP].dst, '0',\
                  dst_ip, src_ip)))
               logging.error(colorred.format(r.summary()))
            else:
               logging.debug(r.summary())
               reply_count = reply_count + 1
        assert reply_count != 0, ("%s=>%s, Expected %d, received %d"
               % (src_ip, dst_ip, cnt, reply_count))
        logging.info(colorgrn.format("%s=>%s, Expected %d, received %d"
                         % (src_ip, dst_ip, cnt, reply_count)))

    @staticmethod
    def send_icmpv6_req(source_ns, dl_src, dl_dst, ipv6_src, ipv6_dst, cnt):
        pkt = Ether(src=dl_src, dst=dl_dst)/IPv6(src=ipv6_src, dst=ipv6_dst)/\
                   ICMPv6EchoRequest(code=0, type=128)
        ans = NetworkUtil.send_pkt_sniff(source_ns, pkt, cnt)
        reply_count = 0
        for s, r in ans:
            code = r[ICMPv6EchoReply].code
            src = r[IPv6].src
            dst = r[IPv6].dst
            if code != 0 or src != pkt[IPv6].dst or dst != pkt[IPv6].src:
               logging.error(colorred.format('Unexpected reply: (code: %s, '
                  'src: %s => dst: %s),'\
                  ' Expected: (code: %s, src: %s => dst: %s)'\
                  %(r[ICMPv6EchoReply].code, r[IPv6].src, r[IPv6].dst, '0',\
                  pkt[IPv6].dst, pkt[IPv6].src)))
               logging.error(colorred.format(r.summary()))
               assert(0)
            else:
               logging.debug(r.summary())
               reply_count = reply_count + 1
        assert reply_count == cnt, ("%s => %s, Expected %d, received %d"
               % (ipv6_src, ipv6_dst, cnt, reply_count))
        logging.info(colorgrn.format("%s=>%s, Expected %d, received %d"
                         % (ipv6_src, ipv6_dst, cnt, reply_count)))
    @staticmethod
    def send_dhcp_request(ns, mac, gw_ip, req_ip):
        loging.info("sending dhcp req MAC: %s" % mac)
        macraw = mac.replace(':','').decode('hex')
        with netns.NetNS(nsname=ns):
             conf.iface = ns+"-veth0"
             conf.verb = 0
             fam,hw = get_if_raw_hwaddr(conf.iface)
             pkt = Ether(src=mac, dst='ff:ff:ff:ff:ff:ff')/\
                   IP(tos=0x10,proto="udp",src="0.0.0.0",dst="255.255.255.255")/\
                   UDP(sport=68,dport=67)/\
                   BOOTP(yiaddr=req_ip, chaddr=macraw)/\
                   DHCP(options=[("message-type", 'request'),
                                 ("requested_addr", req_ip),
                                 ("server_id", gw_ip),
                                 "end"])
             logging.debug("pkt: %s" %pkt.command())
             sendp(pkt, iface=conf.iface)
             looging.info("\tSent DHCP Request for IP (%s)%s"\
                              % (ns+'-veth0', req_ip))
