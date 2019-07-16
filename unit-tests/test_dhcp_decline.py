#!/usr/bin/python
import sys
import os
import time
import json
import subprocess
from pprint import pprint
import netns
import subprocess
import helper
import time
import logging
from threading import Thread
import thread
import multiprocessing
from scapy.all import *
sys.path.append('../config')
reload(sys)
from helper import *

evpn = "0"
dhcp_server_ip = "20.0.0.1"
def learn_ip(ip, count):
    ns = "br2"
    with netns.NetNS(nsname=ns):
        #from scapy.all import *
        conf.iface = "br2-veth0"
        conf.verb=0
        conf.loglevel=error
        pkt = Ether(src='00:00:00:00:00:00', dst='ff:ff:ff:ff:ff:ff')/\
                    ARP(hwdst='ff:ff:ff:ff:ff:ff', psrc=ip, pdst=ip,
                    hwsrc='01:02:03:04:05:06', op=2)
        while(count > 1):
           sendp(pkt)
           count = count -1
    """
    from scapy.all import *
    conf.iface = "br2-vm1-veth1"
    conf.verb = 0
    conf.loglevel=error
    pkt = Ether(src='00:00:00:00:00:00', dst='ff:ff:ff:ff:ff:ff')/\
                ARP(hwdst='ff:ff:ff:ff:ff:ff', psrc=ip, pdst=ip,
                hwsrc='01:02:03:04:05:06', op=2)
    while(count > 0):
          sendp(pkt)
          count = count -1
    """

def setup_module():
    global evpn
    evpn = "101"
    print("\nsetup-module...")

def teardown_module():
    print("teardown-module...")

def test_Dhcp_Discover_Decline(do_assert = True):
    ns = "br1"
    global evpn
    mac = helper.randomMAC()
    results = helper.parse_dhcp_pool_show(evpn)
    print("\n")
    if len(results['Available IP addresses']):
       ip = results['Available IP addresses'][0]
       print("\tFound Free IP %s" % ip)
    else:
       print("\\tNo Free IP available")
       if do_assert:
          assert(0)
    with netns.NetNS(nsname=ns):
         #from scapy.all import *
         conf.iface = ns+"-veth0"
         #conf.iface = "veth1"
         conf.verb = 0
         fam,hw = get_if_raw_hwaddr(conf.iface)
         global dhcp_server_ip
         pkt = Ether(src=mac, dst='ff:ff:ff:ff:ff:ff')/\
               IP(tos=0x10,proto="udp",src="0.0.0.0",dst="255.255.255.255")/\
               UDP(sport=68,dport=67)/\
               BOOTP(yiaddr=ip, chaddr=hw)/\
               DHCP(options=[("message-type", 'discover'),("server_id",\
                                 dhcp_server_ip), "end"])
         print pkt.command()
         sendp(pkt, iface=conf.iface)
         print("\tSent DHCP Discover for IP %s" % ip)
         time.sleep(1)
         results = helper.parse_dhcp_pool_show(evpn)
         if (not helper.array_value_exits(results['Allocated IP addresses'], ip)):
             print("\tIP %s did not get allocated" % ip)
             if do_assert:
                assert(0)
         else:
             print("\tIP %s did get allocated" % ip)
         global dhcp_server_ip
         pkt = Ether(src=mac, dst='ff:ff:ff:ff:ff:ff')/\
               IP(tos=0x10,proto="udp",src="0.0.0.0",dst="255.255.255.255")/\
               UDP(sport=68,dport=67)/\
               BOOTP(chaddr=hw)/\
               DHCP(options=[("message-type", 'decline'),("server_id", \
                           dhcp_server_ip), "end"])
         sendp(pkt, iface=conf.iface)
         time.sleep(1)
    results = helper.parse_dhcp_pool_show(evpn)
    if (not helper.array_value_exits(results['Declined IP addresses'], ip)):
        print("\tIP %s did not get Declined" % ip)
        if do_assert:
           assert(0)
        return False
    else:
        print("\tIP %s did get Declined" % ip)
        return True

def test_dhcp_decline_and_learn_arp():
    print('\n')
    global evpn
    results = helper.parse_dhcp_pool_show(evpn)
    if not len(results['Declined IP addresses']):
       if test_Dhcp_Discover_Decline(False):
          results = helper.parse_dhcp_pool_show(evpn)
       else:
          print("\tNo IP in Declined list")
          assert(0)
    ip = results['Declined IP addresses'][0]
    print("\nIP in Declined list found %s " % ip)

    print("\tLearning IP on br2 %s " %ip)

    send_grat_arp_p = multiprocessing.Process(target=NetworkUtil.send_grat_arp,\
                                              args=('br2', ip))
    send_grat_arp_p.start()
    time.sleep(4)
    """
    with netns.NetNS(nsname="br2"):
        from scapy.all import *
        import thread
        conf.iface = "br2-veth0"
        conf.loglevel=error
        t = Thread(target=learn_ip, args=(ip, 1))
        #thread.start_new_thread(learn_ip, (ip, 100))
        #thread.start_new_thread(learn_ip, (ip, 1))
        t.start()
        t.join()
    """
    results = helper.parse_dhcp_pool_show(evpn)
    if not helper.array_value_exits(results['Allocated IP addresses'], ip):
        print("\tIP %s did not move to allocated" % ip)
        send_grat_arp_p.terminate()
        assert(0)
    else:
        print("\tIP %s did move to allocated" % ip)

    send_grat_arp_p.terminate()
    time.sleep(5)
    results = helper.parse_dhcp_pool_show(evpn)
    if not helper.array_value_exits(results['Available IP addresses'], ip):
        print("\tIP %s did not move to available" % ip)
        assert(0)
    else:
        print("\tIP %s did move to available" % ip)

def test_learn_ip_and_dhcp_decline():
    global evpn
    results = helper.parse_dhcp_pool_show(evpn)
    print("\n")
    if len(results['Available IP addresses']):
       ip = results['Available IP addresses'][0]
       print("\tFound Free IP %s" % ip)
    else:
       print("\\tNo Free IP available")
       assert(0)

    print("\tLearning IP on br2 %s " %ip)
    send_grat_arp_p = multiprocessing.Process(target=NetworkUtil.send_grat_arp,\
                                              args=('br2', ip))
    send_grat_arp_p.start()
    time.sleep(4)
    test_Dhcp_Discover_Decline(False)
    """
    with netns.NetNS(nsname="br2"):
        from scapy.all import *
        import thread
        conf.iface = "br2-veth0"
        conf.loglevel=error
        t = thread.start_new_thread(learn_ip, (ip, 1))
    test_Dhcp_Discover_Decline(False)
    """
    results = helper.parse_dhcp_pool_show(evpn)
    print(results)
    if not helper.array_value_exits(results['Allocated IP addresses'], ip):
        print("\tIP %s did not move to Allocated" % ip)
        send_grat_arp_p.terminate()
        assert(0)
    else:
        print("\tIP %s did move to Allocated" % ip)
    send_grat_arp_p.terminate()
    time.sleep(5)
    results = helper.parse_dhcp_pool_show(evpn)
    print(results)
    if not helper.array_value_exits(results['Available IP addresses'], ip):
        print("\tIP %s did not move to available" % ip)
        assert(0)
    else:
        print("\tIP %s moved to available" % ip)
"""
def test_demo():
    print('\n')
    evpn = "22"
    results = helper.parse_dhcp_pool_show(evpn)
    if not len(results['Declined IP addresses']):
       if test_Dhcp_Discover_Decline(False):
          results = helper.parse_dhcp_pool_show(evpn)
       else:
          print("\tNo IP in Declined list")
          #assert(0)
    ip = results['Declined IP addresses'][0]
    print("\nIP in Declined list found %s " % ip)

    print("\tLearning IP on br2 %s " %ip)
    with netns.NetNS(nsname="br2"):
        from scapy.all import *
        import thread
        conf.iface = "br2-veth0"
        conf.loglevel=error
        t = thread.start_new_thread(learn_ip, (ip, 1))
    learn_ip(ip)
    #t.start()
    time.sleep(2)
    results = helper.parse_dhcp_pool_show(evpn)
    if not helper.array_value_exits(results['Allocated IP addresses'], ip):
        print("\tIP %s did not move to allocated" % ip)
        #assert(0)
    else:
        print("\tIP %s did move to allocated" % ip)
    time.sleep(5)
    results = helper.parse_dhcp_pool_show(evpn)
    if not helper.array_value_exits(results['Available IP addresses'], ip):
        print("\tIP %s did not move to available" % ip)
        #assert(0)
    else:
        print("\tIP %s did move to available" % ip)

"""
