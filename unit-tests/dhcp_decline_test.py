#!/usr/bin/python

import sys
import os
import time
import json
import subprocess
from pprint import pprint
import netns
import subprocess
import thread
from threading import Thread
import multiprocessing
import random

def randomMAC():
    mac = [ 0x00, 0x16, 0x3e,
        random.randint(0x00, 0x7f),
        random.randint(0x00, 0xff),
        random.randint(0x00, 0xff) ]
    return ':'.join(map(lambda x: "%02x" % x, mac))
def test_header(testname, result, count):
    print("\n\nTest Name: "+testname
          +"\nExpected :"+str(count)+ ", Received :"+str(len(result)) +"\t\t\t\t Status: "+
          ("SUCCESS" if (len(result)) else "FAILED")+"\n")
def learn_ip(ns, ip):
    from scapy.all import *
    #ns = "br2"
    print "****learn_ip "+ip
    cnt = 0
    with netns.NetNS(nsname=ns):
         subprocess.call(['ip', 'a'])
         print conf
         conf.iface = ns+"-veth0"
         pkt = Ether(src='00:00:00:00:00:00', dst='ff:ff:ff:ff:ff:ff')/\
               ARP(hwdst='ff:ff:ff:ff:ff:ff', psrc='1.1.1.15', pdst='1.1.1.15',\
               hwsrc=randomMAC(), op=2)
         while(True):
            print "\nsending ..."+str(cnt)
            sendp(pkt)
            time.sleep(4)
            cnt = cnt +1
def make_test(testname, ns, pkt, cnt):
    conf.verb=1
    a, u = srloop(pkt, count=cnt)
    test_header(testname, a, cnt)
"""
ns = "br1"
with netns.NetNS(nsname=ns):
     from scapy.all import *
     conf.iface = ns+"-veth0"
     fam,hw = get_if_raw_hwaddr(conf.iface)
     pkt = IP(tos=0x10,proto="udp",src="0.0.0.0",dst="255.255.255.255")/\
           UDP(sport=68,dport=67)/\
           BOOTP(chaddr=hw)/\
           DHCP(options=[("message-type", 'discover'),("server_id", "1.0.0.1"),
                          "end"])
     #send(pkt)
     pkt = IP(tos=0x10,proto="udp",src="0.0.0.0",dst="255.255.255.255")/\
           UDP(sport=68,dport=67)/\
           BOOTP(chaddr=hw)/\
           DHCP(options=[("message-type", 'decline'),("server_id", "1.0.0.1"),
                          "end"])
     #send(pkt)
p = subprocess.Popen(["ovs-appctl", "evpn/dhcp-pool-show", "alubr0", "22"],
                     stdout=subprocess.PIPE)
print p.communicate()[0]
"""
print "starting thread.. "
#t = Thread(target=myfunc, args=(i,))
#t = Thread(target=learn_ip, args=('br2', '1.1.1.15', 0))
#t = thread.start_new_thread(learn_ip, ("1.1.1.15", 100))
p = multiprocessing.Process(target=learn_ip, args=('br2', '1.1.1.15') )
#t.start()
#time.sleep(10)
#t.join()
p.start()

time.sleep(15)
p.terminate()
