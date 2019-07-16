#!/usr/bin/python

import sys
import os
import time
import json
import subprocess
import re
import uuid
import ipaddr
import random
import argparse
from pprint import pprint
import logging
import select
import socket
import fcntl
import struct

logfile = '/var/tmp/setup.log'
CRED = '\033[91m'
CEND = '\033[0m'

def get_ip_address(ifname):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    return socket.inet_ntoa(fcntl.ioctl(
        s.fileno(),
        0x8915,  # SIOCGIFADDR
        struct.pack('256s', ifname[:15])
    )[20:24])

def get_default_gateway_linux(interface):
    """Read the default gateway directly from /proc."""
    with open("/proc/net/route") as fh:
        for line in fh:
            if interface not in line:
               continue
            fields = line.strip().split()
            if fields[1] != '00000000' or not int(fields[3], 16) & 2:
                continue
            return str(socket.inet_ntoa(struct.pack("<L", int(fields[2], 16))))
    return '0.0.0.0'


def replace_text_in_file(filename, text_to_search, replacement_text):
    logging.info("In %s replaced %s with %s" % (filename, text_to_search, replacement_text))
    s = open(filename).read()
    s = s.replace(text_to_search, replacement_text)
    f = open(filename, 'w')
    f.write(s)
    f.close()
    """
    import fileinput

    with fileinput.FileInput(filename, inplace=True, backup='.bak') as file:
        for line in file:
            print(line.replace(text_to_search, replacement_text), end='')
    """

def call_prog_as_is (cmd, wait_time=None) :
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

class NS_setup(object):
    xml_format = "<domain type='kvm'>\
      <name>%s</name>\
      <uuid>%s</uuid>\
      <description>%s</description>\
     <memory>131072</memory>\
     <os>\
       <type arch='x86_64' machine='rhel6.2.0'>hvm</type>\
     </os>\
     <on_poweroff>destroy</on_poweroff>\
     <on_reboot>restart</on_reboot>\
     <on_crash>restart</on_crash>\
     <devices>\
       <emulator>/usr/libexec/qemu-kvm</emulator>\
       <interface type='bridge'>\
         <mac address='%s'/>\
         <source bridge='alubr0'/>\
         <virtualport type='openvswitch'/>\
         <target dev='%s'/>\
         <model type='rtl8139'/>\
       </interface>\
       </devices>\
    </domain>"

    def __init__(self, n_vms, n_brs):
        self.n_vms = n_vms
        self.n_brs = n_brs
        self.ports = []
        if n_vms:
           for i in range(1, n_vms+1):
               self.ports.append("vm"+str(i))
        if n_brs:
           for i in range(1, n_brs+1):
               self.ports.append("br"+str(i))
        #print "ns_setup: "+str(self.ports)
    def create_xml(self, vm_name = "vm1", dev_name = "vm1-veth1"):
        cmd = 'ip netns exec '+vm_name+' ip a'
        output = subprocess.check_output(cmd, shell=True)
        logging.debug("%s" % output)
        uuid_str = str(uuid.uuid1())
        pattern = 'link/ether ([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})'
        match = re.search(pattern, output)
        m = match.group(0).split()
        mac = m[1]
        f = open('/var/tmp/'+dev_name+'.xml', 'w')
        logging.debug(self.xml_format % (dev_name, uuid_str, uuid_str, mac, dev_name))
        f.write(self.xml_format % (dev_name, uuid_str, uuid_str, mac, dev_name))

    def setup(self):
        for p in self.ports:
            exe("ip netns del "+p)
            exe("ip netns add "+p)
            exe("ip link add "+p+"-veth0 type veth peer name "+p+"-veth1")
            exe("ip link set "+p+"-veth0 netns "+p)
            exe("ip netns exec "+p+" ip link set "+p+"-veth0 up")
            exe("ip netns exec "+p+" ip link set lo up")
            exe("ip link set "+p+"-veth1  up")
            exe("ip netns exec "+p+" sysctl net.ipv4.ip_forward=1")
            self.create_xml(p, p+'-veth1')

    def destroy(self):
        for p in self.ports:
            exe("virsh undefine "+p+"-veth1")
            exe("ip link delete "+p+"-veth1")
            exe("ip netns del "+p)
            exe("rm -f /var/tmp/"+p+"-veth1.xml")
    def get_uuids(self):
        from lxml import etree
        uuids = {}
        for p in self.ports:
            try :
                doc = etree.parse('/var/tmp/'+p+'-veth1.xml')
            except IOError:
                return uuids
            uuidElem = doc.find('uuid')
            uuids[p+'-veth1'] = uuidElem.text
        """
        for u in uuids:
            print ('uuid[%s] => %s' % (u, uuids[u]))
        """
        return uuids
    def get_macs(self):
        macs = {}
        for p in self.ports:
            cmd = 'ip netns exec '+p+' ip a'
            try :
                output = subprocess.check_output(cmd, shell=True)
            except subprocess.CalledProcessError:
                return macs
            #print output
            pattern = 'link/ether ([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})'
            match = re.search(pattern, output)
            if match != None:
               m = match.group(0).split()
               #print m[1]
               macs[p+'-veth1'] = m[1]
        """
        for m in macs:
            print ('macs[%s] => %s' % (m, macs[m]))
        """
        return macs

    def reinit(self):
        self.destroy()
        self.setup()

class ovs_class(object):
    add_flow = "ovs-ofctl add-flow alubr0 "
    del_flow = "ovs-ofctl del-flows alubr0 "
    @staticmethod
    def nsg_iptables_baseline():
        exe('iptables -t nat -N NUAGE_NAT_PAT_PRE')
        exe('iptables -t nat -N NUAGE_NAT_PAT_POST')
        exe('iptables -t nat -A PREROUTING -j NUAGE_NAT_PAT_PRE')
        exe('iptables -t nat -A POSTROUTING -j NUAGE_NAT_PAT_POST')

    @staticmethod
    def netmask_to_nbits(netmask):
        return str(sum([bin(int(x)).count("1") for x in netmask.split(".")]))
    def ovs_get_pid(self):
        current_pid = int(subprocess.check_output(["pidof","ovs-vswitchd"]))
        return current_pid
    def ovs_check_crash(self):
        #ovs_current_pid = int(subprocess.check_output(["pidof","ovs-vswitchd"]))
        #assert ovs_current_pid == self.ovs_pid,\
        ("ovs-vswitchd crashed, new pid %d, old %d" % (ovs_current_pid, self.ovs_pid))

    @staticmethod
    def ovs_bump_gen_id():
        logging.info("ovs gen_id bumped ...")
        exe("ovs-ofctl add-flow alubr0 \"flow_type=ofctl-events,flags=bump_gen_id\"")
    @staticmethod
    def ovs_cleanup():
        exe("ovs-ofctl add-flow alubr0 \"flow_type=ofctl-events,flags=cleanup\"")
        logging.info("ovs cleanup done ...")
    @staticmethod
    def send_pkt_out(in_port, out_port, hexpkt):
        logging.debug("Hex-pkt: %s" % hexpkt)
        exe('ovs-ofctl packet-out alubr0 %s %s %s' % (in_port, out_port, hexpkt))
    @staticmethod
    def ovs_trace(flow):
        logging.info("Tracing flow: %s" % flow)
        r = exe(('ovs-appctl ofproto/trace "%s"' % flow))
        if r[0]:
           return
        r = r[1]
        flows = {}
        ovs_pipeline = []
        for l in r.split('\n'):
            logging.debug(l)
            if 'No match' in l:
               continue
            l = l.strip()
            if 'table=' in l:
               tbl=int(l.split()[1].split('=')[1])
               flows[tbl] = l.split('Rule: ')[1]
               ovs_pipeline.append(tbl)
            elif 'OpenFlow actions=' in l:
               flows[tbl] = flows[tbl]+',actions='+l.split('OpenFlow actions=')[1]
            elif 'Datapath actions:' in l:
               flows['Datapath actions:'] = l.split('Datapath actions:')[1].strip()
        flows['ovs_pipeline'] = ovs_pipeline
        logging.info("Datapath flow table ovs_pipeline: %s"\
                     % (flows['ovs_pipeline']))
        logging.info("Datapath actions: %s"\
                     % (flows['Datapath actions:']))
        return flows

    @staticmethod
    def ovsrec_present_in_ovsdb(table, key, value):
        r = exe("/usr/bin/ovsdb-client transact \'[\"Open_vSwitch\", {\"op\" : \"select\", \"table\" : \"%s\", \"where\" : [[ \"%s\", \"==\", \"%s\"]] } ]'"
                % (table, key, value))
        logging.debug(r)
        return  r[1].strip() != "[{\"rows\":[]}]"
    @staticmethod
    def ovs_get_port(port):
        r = exe(('ovs-appctl dpif/show | grep %s' % port))
        output = r[1].strip()
        if r[0]:
           logging.info("%s does not exists" % port)
        elif len(output):
            user_port=output.split()[1].split('/')[0]
            dp_port=output.split()[1].split('/')[1].split(':')[0]
            logging.debug("%s is at port %s/%s" % (port, user_port, dp_port))
            return [user_port, dp_port]
        return None

    @staticmethod
    def ovs_check_port_exists(port):
        p = subprocess.Popen(["ovs-appctl", "dpif/show"],
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        p1 = subprocess.Popen(('grep', port), stdin=p.stdout,
                              stdout=subprocess.PIPE)
        result = p1.communicate()[0]
        if not len(result):
           logging.info("%s not found" % port)
           return False
        else:
            user_port=result.split()[1].split('/')[0]
            dp_port=result.split()[1].split('/')[1].split(':')[0]
            logging.info("%s is at port %s/%s" % (port, user_port, dp_port))
        return True
    @staticmethod
    def ovs_check_internal_ports():
        for port in ['svc-rl-tap1', 'svc-rl-tap2', 'svc-pat-tap', 'svc-spat-tap']:
            exists = ovs_check_port_exists(port)
            if not exists:
               logging.info("%s not found" % port)
               return False
            else:
               logging.info("%s found" % port)
        return True

    @staticmethod
    def ovs_hit_rules():
        p = subprocess.Popen(["ovs-appctl", "bridge/dump-flows", "alubr0"],
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        p1 = subprocess.Popen(('grep', '-v', 'es=0'), stdin=p.stdout,
                          stdout=subprocess.PIPE)
        result = p1.communicate()[0]
        return result

    @staticmethod
    def expect_rule(pattern, expect, desc=''):
        rule = ovs_class.ovs_find_rule(pattern)
        if expect and not rule:
           assert 0, ('Expected %s rule: %s not found'\
                  % (desc, pattern))
        elif not expect and rule:
           assert 0, ('UnExpected %s(pattern:%s) found, \tRULE: %s'\
                  % (desc, pattern, rule))
           """
           assert 0, ('UnExpected %s rule %s found, rule: %s'\
                  % (desc, pattern, rule))
           """
        logging.info("%s => %s rule: %s" %
                        (desc, ("Found" if expect else "Not found"),\
                        (rule if expect else pattern)))
        return rule

    @staticmethod
    def ovs_flows():
        op = subprocess.check_output(['ovs-appctl',\
                'bridge/dump-flows', 'alubr0'])
        op = re.sub(r'duration.*n_bytes=\d+,', '', op)
        flows = set(op.strip().split('\n'))
        return flows
    @staticmethod
    def ovs_find_rule(pattern):
        op = subprocess.check_output(['ovs-appctl',\
                'bridge/dump-flows', 'alubr0'])
        match = re.search('.*'+pattern+'.*',  op)
        if match:
           #logging.info("found rule : %s" % match.group())
           return match.group()
        return None
    def pg_acl(self, cmd, interface, vm_uuid, pg_tag, acl_type="all",
               action="allow", port_type = "vm"):
        if (acl_type != "all"):
            acl = acl_type
            action_str = ''
            if (cmd == 'add'):
                action_str = ",action="+action
            exe((self.add_flow if (cmd == 'add') else self.del_flow) + "flow_type=acl,type="+port_type+\
                ",priority=0,flags="+acl+",interface="+interface+",vm_uuid="+\
                vm_uuid+",domain_id=1,pg_tag="+pg_tag+action_str)
            #print "----------------------------"
            logging.debug("Configured %s %s ACL %s" % (acl, cmd, interface))
            #print "----------------------------"
        else :
            acls = ["pre", "post", "redirect" ]
            for acl in acls:
                exe( (self.add_flow if (cmd == 'add') else self.del_flow) + "flow_type=acl,type="+port_type+\
                    ",priority=0,flags="+acl+",interface="+interface+",vm_uuid="+\
                    vm_uuid+",action=allow")
                #print "----------------------------"
                logging.debug("Configured %s %s ACL %s" % (acl, cmd, interface))
                #print "----------------------------"
    def get_pg_str(self, tags=[]):
        pg_str =(",domain_id=1,n_pgs=%d" % (len(tags)))
        for t in tags:
           pg_str += (",%s" % t)
        return pg_str
    def route_flow(self, op, flags, vrf_id, evpn_id, vm_ip, vm_mac, is_remote=False):
        cmd = ("ovs-ofctl %s alubr0 flow_type=route,type=vm,ip,flags=%s,"\
               "is_remote=%s,vrf_id=%d,evpn_id=%d,nw_dst=%s,dl_dst=%s"\
               % (('add-flow' if op== 'add' else 'del-flows'), flags, str(is_remote).lower(),\
                   vrf_id, evpn_id, vm_ip, vm_mac))
        exe(cmd)

    def add_remote_vm_route(self, vrf_id, evpn_id, vm_ip, vm_mac):
        self.route_flow('add', "evpn", vrf_id, evpn_id, vm_ip, vm_mac, True)
        self.route_flow('add', 'evpn-redirect', vrf_id, evpn_id, vm_ip, vm_mac, False)
        self.route_flow('add', 'arp-route', vrf_id, evpn_id, vm_ip, vm_mac, False)
    #ovs-ofctl add-flow alubr0 flow_type=route,type=vm,ip,flags=evpn-redirect,vrf_id=2,evpn_id=22,nw_dst=20.1.1.12
    #ovs-ofctl add-flow alubr0 flow_type=route,type=vm,flags=arp-route,ip,vrf_id=2,evpn_id=22,nw_dst=20.1.1.12,dl_dst=3a:fb:ab:9a:12:7f1
    def create_port_cfg(self):
        json_str = ""
        json_str = "{ \n \"hosts\" : \n\t["
        for v in self.vms:
            vm = self.vms[v]
            json_str += "\n\t\t{"
            json_str += ("\n\t\t\t\"%s\" : \"%s\" ," % ('type', 'vm'))
            for i in ['interface', 'mac',  'name', 'uuid']:
                json_str += ("\n\t\t\t\"%s\" : \"%s\" ," % (i, vm[i]))
            json_str += ("\n\t\t\t\"%s\" : %d \n\t\t}," % ('vlan', 0))
            #self.vm_start(vm);
        #time.sleep(1)
        json_str = json_str[:-1]
        json_str += "\n\t]\n}"
        logging.debug("==> %s" % json_str)
        json_dict = eval(json_str)
        with open('/var/tmp/port-cfg', 'w') as f:
                  json.dump(json_dict, f, separators=(', ',':'),
                            sort_keys=True,
                            indent = 4, ensure_ascii=False)
        logging.info("port-cfg Generated ...")

    def vm_restart(self):
        cmd = '/usr/bin/nuage-port-config.pl --secret --add --bridge alubr0 '\
              '--config /var/tmp/port-cfg'
        exe(cmd)

    def auto_gen_vm(self):
        logging.info("Auto-generating VM config ...")
        vm_per_evpn = self.n_vms/len(self.evpns)
        p = self.ports
        all_ports = self.ports
        i = 0
        self.vms = {}
        #print p
        all_evpns = []
        for e in self.evpns:
            if not self.evpns[e].get('skip_auto', False):
               all_evpns.append(e)
        #print all_evpns
        i = 0
        j = 0
        while i < len(all_ports):
            self.vms[all_ports[i]] = {}
            self.vms[all_ports[i]]['interface'] = all_ports[i]
            self.vms[all_ports[i]]['name'] = all_ports[i]

            evpn = self.evpns[all_evpns[j]]
            evpn['vms'].append(all_ports[i])
            self.vms[all_ports[i]]['evpn'] = evpn['properties']['evpn_id']

            nw = self.evpns[all_evpns[j]]['properties']['subnet'] +'/'+\
                 self.netmask_to_nbits(self.evpns[all_evpns[j]]['properties']['mask'])
            network = ipaddr.IPv4Network(nw)
            random_ip = ipaddr.IPv4Address(random.randrange(int(network.network) + 1,\
                                    int(network.broadcast) - 1))
            self.vms[all_ports[i]]['ip'] = str(random_ip)
            if evpn['properties'].get('gw_ipv6'):
               ipv6_nw_str = self.evpns[all_evpns[j]]['properties']['subnetv6'] +\
                             '/112'
               ipv6_nw = ipaddr.IPv6Network(ipv6_nw_str)
               random_ipv6 = ipaddr.IPv6Address(random.randrange(int(ipv6_nw.network) + 1,\
                                    int(ipv6_nw.broadcast) - 1))
               self.vms[all_ports[i]]['ipv6'] = str(random_ipv6)
            i = i + 1
            j = (j + 1) % len(all_evpns)

    def readconfig(self):
        with open(self.cfg_file) as data_file:
            data = json.load(data_file)
        vrfs1 = data['vrfs']
        evpns1 = data['evpns']
        vms1 = data['vms']
        brs1 = data['bridge_ports']
        self.tests = data['tests']
        self.nsg = []
        if "nsg" in data:
           self.nsg = data['nsg']

        vport_macs = self.nss.get_macs()
        uuids = self.nss.get_uuids()
        for v in vrfs1:
            self.vrfs[v['id']] = v
            v['tnl_id'] = v['id']*10
            v['vms'] = []
            v['bps'] = []
            v['evpns'] = []
        for e in evpns1:
            self.evpns[e['properties']['evpn_id']] = e
            e['vms'] = []
            e['bps'] = []
            self.vrfs[e['vrf']]['evpns'].append(e['properties']['evpn_id'])
        #self.template_vm = vms1.get('template')
        #del vms1['template']
        if self.auto_generate:
           for vm in vms1:
               if vm['interface'] == 'template':
                  self.template_vm = vm
           self.auto_gen_vm()
           self.auto_gen_pending = False
        else:
           for vm in vms1:
               self.vms[vm['interface']] = vm
               if vm['interface'] == 'template':
                  continue
           self.template_vm = self.vms['template']
           del self.vms['template']
        """
        print "==========="
        for e in self.evpns:
            print self.evpns[e]
        print "==========="
        #print "\n\n\n"
        #print self.vms
        """
        for i in self.vms:
            vm = self.vms[i]
            if not vm.get('evpn'):
               continue
            vm['mac'] = vport_macs.get(vm['interface'])
            vm['uuid'] = uuids.get(vm['interface'])
            vm['gw_ip'] = self.evpns[vm['evpn']]['properties']['gw_ip']
            vm['gw_ipv6'] = self.evpns[vm['evpn']]['properties'].get('gw_ipv6')
            for p in self.template_vm:
                if vm.get(p) == None:
                   vm[p] = self.template_vm[p]
                   #print("%s: %s" % (vm, self.vms[vm][p]))
            vm['vrf'] = self.evpns[vm['evpn']]['vrf']
            if not self.auto_generate:
               self.evpns[vm['evpn']]['vms'].append(vm['interface'])
            self.vrfs[vm['vrf']]['vms'].append(vm['interface'])
        for bp in brs1:
            bp['mac'] = vport_macs.get(bp['interface'])
            bp['uuid'] = uuids.get(bp['interface'])
            for p in self.template_vm:
                if bp.get(p) == None:
                   bp[p] = self.template_vm[p]
                   #print("%s: %s" % (vm, self.vms[vm][p]))
            bp['vrf'] = self.evpns[bp['evpn']]['vrf']
            self.brs[bp['interface']] = bp

    def __init__(self, cfg_file, n_vms, n_brs, auto_generate = False):
        #self.ovs_pid = int(subprocess.check_output(["pidof","ovs-vswitchd"]))
        self.cfg_file = cfg_file
        self.vrfs = {}
        self.evpns = {}
        self.vms = {}
        self.brs = {}
        self.n_brs = n_brs
        self.n_vms = n_vms
        self.auto_generate = auto_generate
        self.ports = []
        self.nss = NS_setup(n_vms, n_brs)
        self.auto_gen_pending =  True if auto_generate else False
        if n_vms:
           for i in range(1, n_vms+1):
               self.ports.append("vm"+str(i)+'-veth1')
        if n_brs and not auto_generate:
           for i in range(1, n_brs+1):
               self.ports.append("br"+str(i)+'-veth1')
        if not self.auto_generate:
           #self.ns_reinit()
           self.readconfig()
           exe("rm -f /var/tmp/port-cfg")
           self.create_port_cfg()
        else:
           self.readconfig()
        print "ovs_setup: "+str(self.ports)
    def cleanup(self):
        print("Cleaning up ovs configs ...")
        self.nss.destroy()
    def ovs_stop(self):
        #os.system("/usr/share/openvswitch/scripts/openvswitch.init restart")
        #os.system("echo \"ovs_stop\" >> /var/log/openvswitch/ovs-vswitchd.log")
        #exe("echo \"\" > /var/log/openvswitch/ovs-vswitchd.log")
        os.system("/usr/share/openvswitch/scripts/openvswitch.init stop")
    def ovs_start(self):
        #exe ("echo \"\" > /var/log/openvswitch/ovs-vswitchd.log")
        os.system("/usr/share/openvswitch/scripts/openvswitch.init start")

    def ovs_restart(self):
        for tbl in ['Nuage_Port_Provisioning', 'Nuage_BR_Port_Config',
                    'Nuage_Evpn_Dhcp_Pool_Table',
                    'Nuage_Alarms',
                    'Nuage_Route',
                    'Nuage_Evpn_Dhcp_Pool_Dhcp_Entry_Table']:
            cmd = ('/usr/bin/ovsdb-client transact \'["Open_vSwitch", {"op" :'\
                  ' "delete", "table" : "%s", '\
                  '"where" : [ ] } ]\''% tbl)
            exe(cmd)
        #os.system("echo "" > /var/log/openvswitch/ovs-vswitchd.log")
        #os.system("rm -f /var/log/openvswitch/ovs-vswitchd.valgrind*")
        #os.system("/usr/share/openvswitch/scripts/openvswitch.init restart")
        #exe("/usr/share/openvswitch/scripts/openvswitch.init stop")
        #exe("/usr/share/openvswitch/scripts/openvswitch.init start")
        self.ovs_stop()
        self.ovs_start()
        #os.system("service openvswitch restart")
        exe("ovs-appctl vlog/disable-rate-limit")
        exe("ovs-appctl vlog/set any:file:info")
        for log in ['vrs_ofproto',
                    'vrs_ofproto_vrf',
                    'vrs_ofproto_evpn',
                    'vrs_bfd',
                    'vrs_route',
                    #'netdev',
                    #'netlink',
                    #'netlink_socket',
                    #'netlink_notifier',
                    #'dpif_netlink',
                    #'vrs_ofproto_dpif',
                    'vrs_iptables' ]:
            exe(("ovs-appctl vlog/set %s:file:dbg" % log))
        #print "----------------------------"
        #exe(("ovs-appctl vlog/set dbg"))
        logging.info("ovs restart done.")
        #print "----------------------------"

    def vm_add_port(self, vm):
        exe("ovs-vsctl add-port alubr0 "+vm['interface'], True)
    def ns_reinit(self):
        self.nss.destroy()
        self.nss.setup()
        self.readconfig()
        exe("rm -f /var/tmp/port-cfg")
        self.create_port_cfg()
    def ns_vm_dhcp(self):
        for v in self.vms:
            vm = self.vms[v]
            if vm.get('isfake') == "False":
              continue
            token = vm["interface"].split("-")
            peer = token[0] +"-veth0"
            logging.debug("\n### ipv4 address config: Evpn: %s, %s = > %s" %(vm['evpn'], peer, vm['ip']))
            if self.evpn_flag_enabled(int(vm['evpn']), 'l3_proxy'):
               netmask = self.netmask_to_nbits(self.evpns[int(vm['evpn'])]['properties']['mask'])
               for op in ['del', 'add']:
                   exe(("ip netns exec %s ip addr %s %s/%s dev %s"
                       % (token[0], op, vm['ip'], netmask, peer)), True)
                   exe(("ip netns exec %s ip route %s %s/%s dev i%s"
                       % (token[0], op, vm['ip'], netmask, peer)), True)
                   exe(("ip netns exec %s ip route %s default via %s"
                       % (token[0], op, vm['gw_ip'])), True)
               """
               exe("ip netns exec %s ip addr add %s/%s dev %s"% (token[0], vm['ip'], netmask, peer))
               exe("ip netns exec %s ip route add %s/%s dev %s"% (token[0], vm['ip'], netmask, peer))
               exe("ip netns exec %s ip route add default via %s "% (token[0], vm['gw_ip']), True)
               """
            else:
               exe("ip netns exec %s dhclient -v -r %s" % (token[0], peer), True)
               exe("ip netns exec %s dhclient -v %s" % (token[0], peer), True)
            if self.evpn_ip6_enabled(vm['evpn']) and vm.get('ipv6'):
               logging.debug("### ipv6 address config: %s = > %s" %(peer, vm['ipv6']))
               exe(("ip netns exec %s ip -6 addr del %s/64 dev %s"% (token[0], vm['ipv6'], peer)), True)
               exe(("ip netns exec %s ip -6 route del %s/64 dev i%s"% (token[0], vm['ipv6'], peer)), True)
               exe(("ip netns exec %s ip -6 route del default via %s "% (token[0], vm['gw_ipv6'])), True)
               exe("ip netns exec %s ip -6 addr add %s/64 dev %s"% (token[0], vm['ipv6'], peer))
               exe("ip netns exec %s ip -6 route add %s/64 dev %s"% (token[0], vm['ipv6'], peer))
               exe("ip netns exec %s ip -6 route add default via %s "% (token[0], vm['gw_ipv6']), True)
        logging.info("All VMs Dhcp Done.")

    def vm_start(self, vm):
        if vm.get('isfake') == "False":
           exe("virsh destroy "+vm['interface'])
        exe("virsh undefine "+vm['interface'])
        exe("virsh define  /var/tmp/"+vm['interface']+".xml")
        if vm.get('isfake') == "False":
           exe("virsh start "+vm['interface']);
        #print "----------------------------"
        logging.debug("VM % started .." % vm['interface'])
        #print "----------------------------"

    def add_vrf(self, vrf, tnl_id, vrf_flags, tnl_type='vxlan'):
        vrf_flags_str = ""
        if vrf_flags:
           for flag in vrf_flags:
               vrf_flags_str += flag +"=true,"
        if len(vrf_flags_str):
            vrf_flags_str = vrf_flags_str[:-1]
        exe("ovs-ofctl add-vrf alubr0 %s %s %s,type=%s"
            %(str(vrf), str(tnl_id), vrf_flags_str, tnl_type))
        #print "----------------------------"
        logging.debug("vrf %s Created .." % str(vrf))
        #print "----------------------------"

    def add_evpn(self, evpn, vrf, flags, tnl_id, subnet, mask, gw_ip, gw_mac,\
                 v6_subnet, v6_mask, v6_gw, dhcp_pool_range):
        flags_str = ""
        for f in flags.split(','):
            flags_str = flags_str + "flags="+f+","
        exe("ovs-ofctl add-evpn alubr0 "+str(vrf)+" evpn_id="+str(evpn)+\
            ",vni_id="+str(tnl_id)+","+flags_str+"subnet="+subnet+",mask="+\
            mask+",gw_ip="+gw_ip+",gw_mac="+gw_mac+",subnetv6="+v6_subnet+\
            ",gw_ipv6="+v6_gw+",maskv6="+v6_mask+",dhcp_pool_range="+\
            dhcp_pool_range)
        #print "----------------------------"
        print evpn
        logging.debug("evpn %s Created .." % str(evpn))
        #print "----------------------------"

    def vm_evpn_membership(self, interface, evpn, vm_uuid, port_type = "vm"):
        exe(self.add_flow + "flow_type=route,type="+port_type+\
            ",ip,flags=membership,evpn_id="+str(evpn)+\
            ",interface="+str(interface)+",vm_uuid="+vm_uuid)

        #print "----------------------------"
        logging.debug("Associated %s with evpn %s" % (interface, str(evpn)))
        #print "----------------------------"

    def vm_acl(self, interface, evpn, vm_uuid, port_type = "vm"):
        acls = ["pre", "post", "redirect" ]
        for acl in acls:
            exe(self.add_flow + "flow_type=acl,type="+port_type+\
                ",priority=0,flags="+acl+",interface="+interface+",vm_uuid="+\
                vm_uuid+",action=allow")
            #print "----------------------------"
            logging.debug("Configured %s ACL %s" % (acl, interface))
            #print "----------------------------"

    def vm_dhcp_info(self, interface, evpn, vm_uuid, proto, vm_ip):
        exe(self.add_flow + "flow_type=dhcp,interface="+interface+",vm_uuid="+\
            vm_uuid+","+proto+"="+vm_ip)
        #print "----------------------------"
        logging.debug("Associated %s with dhcp entry %s" % (interface, vm_ip))
        #print "----------------------------"

    def vm_fips(self, interface, uuid, vm_ip, vrf, fip, pub_vrf,\
                port_type = "vm", op = 'add'):
        exe((self.add_flow if op == 'add' else self.del_flow)+\
            "flow_type=route,type="+port_type+\
            ",ip,flags=nat,vrf_id="+str(vrf)+",interface="+interface+\
            ",vm_uuid="+uuid+",nw_dst="+vm_ip+",public_ip="+fip+",pub_vrfid="+\
            str(pub_vrf))
        #print "----------------------------"
        logging.debug("%sAssociated %s  with fip %s" % (('Dis-' if op == "delete" else ""),\
              interface, fip))
        #print "----------------------------"

    def vm_enable_mac_learning(self, vm, port_type = "vm"):
        exe(self.add_flow + "flow_type=route,type="+port_type+\
            ",flags=enable-learning,interface="+vm['interface']+",vm_uuid="+\
            vm['uuid'])

    def vm_routes(self, vm, proto, vrf, evpn, interface, vm_uuid, vm_ip,\
                  vm_mac, port_type = "vm"):
        dst = ('nw_dst' if proto == 'ip' else 'ipv6_dst')
        exe(self.add_flow + "flow_type=route,type="+port_type+\
            ",flags=evpn,vrf_id="+str(vrf)+",evpn_id="+str(evpn)+",interface="+\
            str(interface)+",vm_uuid="+vm_uuid+\
            ("" if (port_type != "vm") else (",dl_dst="+vm_mac))+self.get_pg_str([vrf, evpn]))
        netmask = self.evpns[evpn]['properties']['mask']
        exe(self.add_flow + "flow_type=route,type="+port_type+","+proto+\
            ",flags=evpn-redirect,vrf_id="+str(vrf)+",evpn_id="+str(evpn)+","+\
            dst+"="+ (vm_ip if (port_type == "vm") \
                      else self.evpns[evpn]['properties']['subnet']
                      +'/'+self.netmask_to_nbits(netmask)) +self.get_pg_str([vrf, evpn]))
        exe(self.add_flow+ "flow_type=qos,interface="+str(interface)+",type="+\
            port_type+",""vm_uuid="+vm_uuid+","\
            "ingress_rate="+str(vm['ingress_rate'])+",ingress_peak_rate="+\
            str(vm['ingress_peak_rate'])+",ingress_burst="+\
            str(vm['ingress_burst'])+","\
            "ingress_bum_rate="+str(vm['ingress_bum_rate'])+\
            ",ingress_bum_peak_rate="+str(vm['ingress_bum_peak_rate'])+\
            ",ingress_bum_burst="+str(vm['ingress_bum_burst'])+","\
            "ingress_fip_rate="+str(vm['ingress_fip_rate'])+\
            ",ingress_fip_peak_rate="+str(vm['ingress_fip_peak_rate'])+\
            ",ingress_fip_burst="+str(vm['ingress_fip_burst'])+","\
            "egress_fip_rate="+str(vm['egress_fip_rate'])+\
            ",egress_fip_peak_rate="+str(vm['egress_fip_peak_rate'])+\
            ",egress_fip_burst="+str(vm['egress_fip_burst'])+","\
            "egress_class="+str(vm['egress_class']))
        if (port_type == "vm"):
            exe(self.add_flow + "flow_type=route,type="+port_type+\
                ",flags=arp-route,"+proto+",vrf_id="+str(vrf)+\
                ",evpn_id="+str(evpn)+","+dst+"="+vm_ip+\
                ("" if (port_type != "vm") else ",dl_dst="+vm_mac)+self.get_pg_str([vrf, evpn]))
        #print "----------------------------"
        logging.debug("vm routes added for %s ip: %s" % (interface, vm_ip))
        #print "----------------------------"

    @staticmethod
    def ofctlby_property_entry(base, v):
        v_exclude = []
        if v.get('exclude', "None")!= "None":
           v_exclude = v['exclude']
        cmd = ""
        for p in v['properties']:
            #print p +" -> "+str(v['properties'][p])
            if p in v_exclude:
               logging.debug("skiping .. %s" % p)
               continue
            if str(v['properties'][p]).find(',') != -1:
               attr_str = ""
               for f in str(v['properties'][p]).split(','):
                       attr_str = attr_str + p +"="+f+","
               cmd = cmd +attr_str+","
            else:
               cmd = cmd +p+"="+str(v['properties'][p])+","
        if v.get('vrf', 'none') != 'none':
           cmd = str(v['vrf'])+" "+cmd
        exe(base +" "+ cmd)

    def evpn_delete (self, evpn_id):
        logging.info("Evpn DELETE 0x%x " % int(evpn_id))
        self.ofctlby_property_entry('ovs-ofctl del-evpn alubr0',
                               self.evpns[int(evpn_id)])
    def evpn_mod_flag(self, evpn_id, flag, enable):
        if flag is not "dummy":
           logging.info("Evpn 0x%x %s %s flag" %
                        ((int(evpn_id)), "ENABLE" if enable else "DISABLE", flag))
        cur_flags = self.evpns[int(evpn_id)]['properties']['flags']
        if not enable:
           self.evpns[int(evpn_id)]['properties']['flags'] = cur_flags.replace(flag, '')
        else:
           self.evpns[int(evpn_id)]['properties']['flags'] = cur_flags+','+flag
        self.ofctlby_property_entry('ovs-ofctl add-evpn alubr0',
                               self.evpns[int(evpn_id)])
    def evpn_create (self, evpn_id):
        logging.info("Evpn CREATE 0x%x " % int(evpn_id))
        self.evpn_mod_flag(evpn_id, 'dummy', False)

    def vrf_create (self, vrf_id):
        logging.info("VRF CREATE 0x%x " % int(vrf_id))
        vrf = self.vrfs[vrf_id]
        self.add_vrf(vrf['id'], vrf['tnl_id'], vrf.get('vrf_flags'),
                     vrf.get('type', 'vxlan'))
    def ofctlby_property(self, base, values):
        for i in values:
            v = values[i]
            self.ofctlby_property_entry(base, v)
            """
            v_exclude = []
            if v.get('exclude', "None")!= "None":
               v_exclude = v['exclude']
            cmd = ""
            for p in v['properties']:
                #print p +" -> "+str(v['properties'][p])
                if p in v_exclude:
                   logging.debug("skiping .. %s" % p)
                   continue
                if str(v['properties'][p]).find(',') != -1:
                   attr_str = ""
                   for f in str(v['properties'][p]).split(','):
                       attr_str = attr_str + p +"="+f+","
                   cmd = cmd +attr_str+","
                else:
                   cmd = cmd +p+"="+str(v['properties'][p])+","
            if v.get('vrf', 'none') != 'none':
                cmd = str(v['vrf'])+" "+cmd
            exe(base +" "+ cmd)
            """

    def bridge_port_setup(self):
        for i in self.vrfs:
            vrf = self.vrfs[i]
            self.add_vrf(vrf['id'], vrf['tnl_id'], vrf.get('vrf_flags'),
                         vrf.get('type', 'vxlan'))
        self.ofctlby_property('ovs-ofctl add-evpn alubr0', self.evpns)
        for i in self.brs:
            p = self.brs[i]
            exe("nuage-sw-gwcli.pl --add --name "+p['interface']\
                +" --type bridge  --vlan 0 --interface "+p['interface']\
                +" --uuid "+p['uuid'])
            self.vm_evpn_membership(p['interface'], p['evpn'], p['uuid'],\
                                    "bridge")
            self.vm_acl(p['interface'], p['evpn'], p['uuid'], "bridge")
            self.vm_routes(p, 'ip', p['vrf'], p['evpn'], p['interface'],\
                           p['uuid'], p['ip'], p['mac'], "bridge")
            self.vm_enable_mac_learning(p, "bridge")
    def evpn_flag_enabled(self, evpn_id, flag):
        return (flag not in self.evpns[evpn_id]['exclude'] and \
               flag in self.evpns[evpn_id]['properties']['flags'])

    def evpn_ip6_enabled(self, evpn_id):
        return (self.evpns[evpn_id].get('exclude') == None or \
                'subnetv6' not in self.evpns[evpn_id]['exclude']) and \
               self.evpns[evpn_id]['properties'].get('subnetv6') != None

    def evpn_ip6_enabled(self, evpn_id):
        return (self.evpns[evpn_id].get('exclude') == None or \
                'subnetv6' not in self.evpns[evpn_id]['exclude']) and \
               self.evpns[evpn_id]['properties'].get('subnetv6') != None
    def vm_ipv6_enabled(self, vm):
        return self.vms[vm].get('ipv6') \
               and self.evpn_ip6_enabled(self.vms[vm]['evpn'])


    def vm_port_setup(self):
        self.vm_restart()
        for i in self.vrfs:
            vrf = self.vrfs[i]
            self.add_vrf(vrf['id'], vrf['tnl_id'], vrf.get('vrf_flags'),
                         vrf.get('type', 'vxlan'))
        self.ofctlby_property('ovs-ofctl add-evpn alubr0', self.evpns)
        for i in self.evpns:
            e = self.evpns[i]
            netmask = e['properties']['mask']
            exe(self.add_flow + "flow_type=route,type=vm,ip"+\
                ",flags=evpn-redirect,vrf_id="+str(e['vrf'])+",evpn_id="+str(i)+","+\
                "nw_dst="+ e['properties']['subnet']+'/'+self.netmask_to_nbits(netmask)+self.get_pg_str([i]))
        for v in self.vms:
            vm = self.vms[v]
            self.vm_add_port(vm)
            self.vm_evpn_membership(vm['interface'], vm['evpn'], vm['uuid'])
            self.vm_acl(vm['interface'], vm['evpn'], vm['uuid'])
            self.vm_routes(vm, 'ip', vm['vrf'], vm['evpn'], vm['interface'],\
                      vm['uuid'], vm['ip'], vm['mac'])
            self.vm_dhcp_info(vm['interface'], vm['evpn'], vm['uuid'], 'ip',\
                              vm['ip'])
            if self.evpn_ip6_enabled(vm['evpn']) and vm.get('ipv6'):
               logging.debug("evpn %d ipv6 enabled" % vm['evpn'])
               self.vm_dhcp_info(vm['interface'], vm['evpn'], vm['uuid'],\
                                 'ipv6', vm['ipv6'])
               self.vm_routes(vm, 'ipv6', vm['vrf'], vm['evpn'], vm['interface'],\
                              vm['uuid'],vm['ipv6'], vm['mac'])
            else:
               logging.debug("evpn %d ipv6 disabled" % vm['evpn'])
            logging.debug("-----------------")
            self.vm_enable_mac_learning(vm, "vm")
        logging.info("Done vm_port_setup ...")

    def fip_config(self, op = "add"):
        for v in self.vms:
            vm = self.vms[v]
            if not vm.get('fip'):
               continue
            self.vm_fips(vm['interface'], vm['uuid'], vm['ip'], vm['vrf'],\
                         vm['fip'], vm['pub_vrf'], "vm", op)
    def fip_ecmp_route_delete(self):
        for v in self.vms:
            vm = self.vms[v]
            if not vm.get('fip'):
               continue
            exe(self.del_flow + "flow_type=route,ip,flags=ecmp,vrf_id="+\
                str(vm['pub_vrf'])+",nw_dst="\
                +vm['fip']+",n_hop=0\|1\|0,nhop_flag=remote");
            logging.info("Deleted ecmp route for fip %s, vrf 0x%x"\
                         % (vm['fip'], vm['pub_vrf']))
    def local_CE_static_route(self, prefix, nhops, vrf_id):
        nh_str = ""
        for nh in nhops:
           nh_str += ("nhop_flag=local_ce,tep_addr=%s," % nh)
        nh_str = ("n_hop=0\|0\|%d,%s" % (len(nhops), nh_str))
        exe((self.add_flow + "flow_type=route,ip,flags=ecmp,vrf_id=%s,"\
            "nw_dst=%s,%s" % (vrf_id, prefix, nh_str)))
        logging.debug("local static ecmp remote route added for %s in vrf %s,"\
                      " next-hop: %s"% (prefix, str(vrf_id), nhops))
    def local_static_route(self, prefix, nhops, vrf_id):
        nh_str = ""
        for nh in nhops:
           nh_str += ("nhop_flag=local,lhop_interface=%s," % nh)
        nh_str = ("n_hop=%d\|0\|0,%s" % (len(nhops), nh_str))
        exe((self.add_flow + "flow_type=route,ip,flags=ecmp,vrf_id=%s,"\
            "nw_dst=%s,%s" % (vrf_id, prefix, nh_str)))
        logging.debug("local static ecmp remote route added for %s in vrf %s,"\
                      " next-hop: %s"% (prefix, str(vrf_id), nhops))
    def vif_routes(vrf, ip, underlay_id,  nsg_dpid):
        cmd = ("ovs-ofctl add-flow alubr0 flow_type=route,ip,flags=ecmp,"\
               "vrf_id=%s,nw_dst=%s,n_hop=0\|1\|0,"\
               "ecmp_flags=vif_mapping_vxlan,"\
               "nhop_flag=remote,underlay_id=%s,vif_dpid=%s"\
               %(str(vrf), str(ip), str(underlay_id), str(nsg_dpid)))
        exe(cmd)
        cmd = ("ovs-ofctl add-flow alubr0 flow_type=route,ip,flags=ecmp,"\
              "vrf_id=%s,nw_dst=%s,n_hop=0\|1\|0,nhop_flag=remote,"\
              "rnhop_flag=nhop_vif,tep_addr=%s"\
              % (str(vrf), str(ip), str(nsg_dpid)))
        exe(cmd)
    def vip_routes(vip_type, vm_uuid, interface, ip, mac="00:00:00:00:00:00"):
        cmd = ("ovs-ofctl add-flow alubr0 flow_type=route,flags=%s,"\
              "vm_uuid=%s,interface=%s,n_v4_entries=1,vip_ipv4=%s"\
              ",vip_mac_ipv4=%s" % (vip_type, vm_uuid, interface, ip, mac))
        exe(cmd)
    def static_routes(self):
        #ovs-ofctl add-flow alubr0 flow_type=route,ip,flags=ecmp,vrf_id=1,
        #nw_dst=50.50.50.51,n_hop=1\|0,nhop_flag=local,
        #vm_uuid=79fc3bf2-f009-11e7-bcb4-080027f6b007,
        #lhop_interface=vm1-veth1,port_mac=a2:f0:e2:2f:09:5f,vni_id=20
        for i in self.vrfs:
            vrf = self.vrfs[i]
            for rt in vrf['static_routes']:
                exe(self.add_flow + "flow_type=route,ip,flags=ecmp,vrf_id="+\
                    str(vrf['id'])+",nw_dst="\
                    +rt['ip']+",n_hop=0\|1\|0,nhop_flag=remote,mvpn_id="\
                    +str(vrf['id']*11)+",tep_addr="+rt['tep_addr'])
                #print "----------------------------"
                logging.debug("static ecmp remote route added for %s in vrf %s"\
                      % (rt['ip'], str(vrf['id'])))
                #print "----------------------------"
    @staticmethod
    def add_static_dhcp_map(evpn, ip, mac, more=False):
        exe("ovs-ofctl add-flow alubr0 flow_type=static_dhcp,evpn_id=%d,"\
            "dl_src=%s,nw_src=%s,is_more=%s,action=allow"
            % (int(evpn), ip, mac, str(more)))
    def print_qos_cfg(self):
        clis = ["qdisc", "class", "filter" ]
        logging.info("\n********* Ingress fip qos  *********")
        for c in clis:
            os.system("tc -p -s -d "+c+" show dev svc-rl-tap1")

        for v in self.vms:
            vm = self.vms[v]
            logging.info("\n********* Egress fip qos for "+vm['interface']+ " *********")
            for c in clis:
                os.system("tc -p -s -d "+c+" show dev "+vm['interface'])
    def print_topology(self):
        logging.info('\nVRS Topology:')
        for v in self.vrfs:
            vrf = self.vrfs[v]
            logging.info('\tvrf_id: %d(0x%x)' % (v, v))
            for e in vrf['evpns']:
                evpn = self.evpns[e]
                logging.info('\t    evpn_id: %d(0x%x) GW: %s GWv6: %s' %
                             (e, e, evpn['properties']['gw_ip'],
                              evpn['properties'].get('gw_ipv6')))
                for vm in evpn['vms']:
                    ip = self.vms[vm]['ip']
                    ipv6 = self.vms[vm].get('ipv6')
                    logging.info('\t\t\t[ %s ]\n\t\t\t ip:%-16s %-128s'
                                 % (vm, ip, (ipv6 if ipv6 else "")))
                    if self.vms[vm].get('fip'):
                       logging.info('\t\t\t\t[ FIP ] : %-16s 0x%x' %
                                    (self.vms[vm]['fip'], int(self.vms[vm]['pub_vrf'])))

    def port_show(self, port_type = "vm"):
        os.system("ovs-appctl "+port_type+"/port-show");

    def vm_port_show(self):
        self.port_show()

    def bridge_port_show(self):
        self.port_show("bridge")

    def vrf_show(self):
        os.system("ovs-appctl vrf/show alubr0");
    def evpn_show(self):
        os.system("ovs-appctl evpn/show alubr0");
    def print_setup_log(self):
        os.system("cat /var/tmp/setup.log");
    def nsg_uplink_resolution(self):
        r = exe('pwd')
        cur_dir = r[1].strip()
        exe(('ln -s %s /home/root' % cur_dir))
        r = exe("ip route list table uplink1")
        if (r[0]):
            exe("echo 200 uplink1 >> /etc/iproute2/rt_tables")
            exe("ip rule del priority 32762")
            exe("ip rule del priority 32763")
            exe("ip rule add from all fwmark 0x80000/0x1ff80000 lookup uplink1 priority 32762")
            exe("ip rule add from all fwmark 0x80000/0x1ff80000 blackhole priority 32763")
        else:
            exe("ip route flush table uplink1")
        r = exe("ip route list table uplink2")
        if (r[0]):
            r = exe("echo 201 uplink2 >> /etc/iproute2/rt_tables")
            exe("ip rule del priority 32760")
            exe("ip rule del priority 32761")
            exe("ip rule add fwmark 0x100000/0x1ff80000 table uplink2 priority 32760")
            exe("ip rule add blackhole fwmark 0x100000/0x1ff80000 priority 32761")
        else:
            exe("ip route flush table uplink2")

        exe('pip install redis')
        exe('pip install netaddr')
        exe('cp /etc/NetworkManager/dispatcher.d/nuage-dhcp-hook'
            ' /var/tmp/nuagedhcphook.py')
        sys.path.insert(0, '/var/tmp')
        from nuagedhcphook import update_underlay

        for u in self.nsg:
            for f in ['/home/root/nsg-agent/configs/mergedconfig.json',
                      '/home/root/nsg-agent/nsg-state.json' ]:
                replace_text_in_file(f, str(u['nsg_port']), str(u['port_name']))
            logging.info('setting up %s ...' % u)
            intf = str(u['port_name'])
            pp_alias=""
            priority= u['priority']
            table= u['table']
            reason="up"
            standbyController=activeController="0.0.0.0"
            uplinkSecondaryIp=None
            bs_status=""
            uplink_flags= u['uplink_flags']
            ip=str(get_ip_address(intf))

            os.environ['IP4_ADDRESS_0'] = ip+'/24 '+get_default_gateway_linux(intf)

            static_ip = os.environ['IP4_ADDRESS_0'].split()[0]
            static_ip, static_ip_len = static_ip.split('/')

            os.environ['DHCP4_IP_ADDRESS'] = ip
            os.environ['DHCP4_ROUTERS'] = os.environ['IP4_ADDRESS_0'].split()[1]
            os.environ['IP4_NAMESERVERS'] = os.environ['DHCP4_ROUTERS']

            parts = static_ip.split(".")
            int_ip = int(parts[0]) | (int(parts[1]) << 8) |\
                      (int(parts[2]) << 16) | (int(parts[3]) << 24)
            int_mask = (2 << int(static_ip_len) - 1) - 1
            os.environ['DHCP4_NETWORK_NUMBER'] = socket.inet_ntoa(struct.pack('I',int_ip & int_mask))

            update_underlay(pp_alias, intf, priority, table, reason,
                            activeController, standbyController, uplinkSecondaryIp,
                            bs_status, uplink_flags,ip, os.environ['DHCP4_NETWORK_NUMBER']
                            ,get_default_gateway_linux(intf)
 )
            for f in ['/home/root/nsg-agent/configs/mergedconfig.json',
                      '/home/root/nsg-agent/nsg-state.json' ]:
                replace_text_in_file(f, str(u['nsg_port']), str(u['port_name']))
        #exe('unlink /home/root')

class Menu :
    def __init__(self, menu, cfg_file="None", verbose = False):
        self.menu = menu
        self.cfg_file = cfg_file
        self.verbose = verbose
    def run (self):
        while True:
            print("Config-File : %s"% (self.cfg_file))
            if os.path.exists(logfile) and os.path.getsize(logfile) >= 2000:
               os.system("echo ""  > "+logfile)
            for m in self.menu:
                print("\t%-3s  %-32s %s " % (str(m)+\
                      '.', self.menu[m][0],\
                      ("" if len(self.menu[m]) <  3 or not self.verbose   else   '[ '+\
                       self.menu[m][2]+' ]')))
            ch = raw_input("Choose ? ")
            print ""
            if not ch.isdigit():
               continue;
            if (len(self.menu) -1) >= int(ch):
                self.menu[int(ch)][1]()

def main(argv):
    parser = argparse.ArgumentParser()
    parser.add_argument("--cfg-file", default='config.json', help="JSON config-file")
    parser.add_argument("--vms",  default=16, help="Number of vm-vports", type=int)
    parser.add_argument("--brs",  default=4, help="Number of bridge-vports", type=int)
    parser.add_argument("--dynamic", "--dynamic",action="store_true",\
                        help="Generate vms, ips dynamically")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Increase output verbosity")
    args = parser.parse_args()

    print args
    if args.verbose:
       logging.basicConfig(format='', level=logging.DEBUG)
       logging.basicConfig(format='', level=logging.INFO)
       #logging.basicConfig(format='%(levelname)s:%(message)s ', level=logging.DEBUG)
    else:
       #logging.basicConfig(format='%(levelname)s:%(message)s ', level=logging.INFO)
       logging.basicConfig(format='', level=logging.INFO)
    cfg_file = args.cfg_file
    ovs = ovs_class(cfg_file, args.vms, args.brs, args.dynamic)
    menu = {
             0: [ 'ovs-restart', ovs.ovs_restart, "Restart the OVS" ],
             1: [ 'VRS setup', ovs.vm_port_setup,\
                                   "setup routes for vm resolution" ],
             2: [ 'NSG setup', ovs.bridge_port_setup,\
                                   "setup routes for bridge port resolution" ],
             3: [ 'remote static routes', ovs.static_routes,\
                                   "configure static routes" ],
             4: [ 'fip config', ovs.fip_config,\
                                   "configure fip routes" ],
             5: [ 'vrf/show', ovs.vrf_show ],
             6: [ 'evpn/show', ovs.evpn_show ],
             7: [ 'vm/port-show', ovs.vm_port_show ],
             8: [ 'bridge/port-show', ovs.bridge_port_show ],
             9: [ 'Egress fip qos config show', ovs.print_qos_cfg ],
             10: [ 'Topology', ovs.print_topology,\
                      "current topoloy, may need to re-init in  case of auto-generate"],
             11: [ 'VM DHCP', ovs.ns_vm_dhcp,\
                      "dhclient for vports, assign ipv6 if configured"],
             12: [ 're intialize', ovs.ns_reinit,\
                      "destroy and recreate namespaces, xmls, veth pairs"],
             13: [ 'Cleanup', ovs.cleanup,\
                      "destroy namespaces, xmls, veth pairs"],
             14: [ 'Nsg uplink setup', ovs.nsg_uplink_resolution,\
                      "NSG uplink resolution"],

        }
    menu_object = Menu(menu, cfg_file, args.verbose)
    menu_object.run()

if __name__ == "__main__":
   main(sys.argv[1:])
