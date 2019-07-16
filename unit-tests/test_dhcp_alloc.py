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
import xml.etree.ElementTree as ET
sys.path.append('../config')
reload(sys)
from helper import *
sys.setdefaultencoding('utf8')

evpn = "0"
dhcp_server_ip = "20.0.0.1"
ovs = {}
vrfs = {}
evpns = {}
vms = {}
brs = {}
tests = {}
scenario = {}

ovs = ovs_class('../config/config.json', 16 , 4)
def setup_module():
    global evpn
    evpn = "101"
    print("\nsetup-module...")
    global ovs
    global vrfs
    global evpns
    global vms
    global brs
    global tests
    global scenario

    ovs.readconfig()
    vrfs = ovs.vrfs
    evpns = ovs.evpns
    vms = ovs.vms
    brs = ovs.brs
    tests = ovs.tests

def teardown_module():
    print("teardown-module...")

def handle_dhcp(pkt):
    if pkt[DHCP]:
        if pkt[DHCP].options[0][1]==5:
            print str(pkt[IP].dst)+" registered"
            print pkt.command()
        elif pkt[DHCP].options[0][1]==6:
            print "NAK received"

def listen():
    # sniff DHCP packets
    sniff(filter="udp and (port 67 or port 68)",
          prn=handle_dhcp, store=0)

@pytest.mark.skip(reason="Needs some work, threads not working as supposed to be.")
def test_Dhcp_Alloc():
    thread = Thread(target=listen)
    thread.start()
    print("\n")
    ns = "br1"
    global ovs
    alloc_list = {}
    for i in range(0, 2):
        #mac = brs[ns+'-veth1']['vports'][i]
        mac = helper.randomMAC()
        results = helper.parse_dhcp_pool_show(evpn)
        if len(results['Available IP addresses']):
           ip = results['Available IP addresses'][0]
           print("found Free IP %s" % ip)
        else:
           print("no Free IP available")
           assert(0)
        print mac
        e = evpns[brs[ns+'-veth1']['evpn']]['properties']
        with netns.NetNS(nsname=ns):
            conf.iface = ns+"-veth0"
            conf.verb = 0
            fam,hw = get_if_raw_hwaddr(conf.iface)
            pkt = Ether(src=mac, dst='ff:ff:ff:ff:ff:ff')/\
               IP(tos=0x10,proto="udp",src="0.0.0.0",dst="255.255.255.255")/\
               UDP(sport=68,dport=67)/\
               BOOTP(yiaddr=ip, chaddr=RandString(12, "0123456789abcdef"))/\
               DHCP(options=[("message-type", 'discover'),
                             ("requested_addr", ip),
                             ("server_id", e['gw_ip']),
                             "end"])
            print pkt.command()
            a, u = srp(pkt, iface=conf.iface)
            print("\tSent DHCP Discover for IP %s" % ip)
            print a
            print u

            time.sleep(1)
            results = helper.parse_dhcp_pool_show(evpn)
            if (not helper.array_value_exits(results['Allocated IP addresses'], ip)):
                print("\tIP %s did not get allocated" % ip)
                assert(0)
            else:
                print("\tIP %s did get allocated" % ip)

            alloc_list[ip] = mac
            print alloc_list
            """
            pkt = Ether(src=mac, dst='ff:ff:ff:ff:ff:ff')/\
               IP(tos=0x10,proto="udp",src="0.0.0.0",dst="255.255.255.255")/\
               UDP(sport=68,dport=67)/\
               BOOTP(chaddr=hw)/\
               DHCP(options=[("message-type", 'release'),("server_id", \
                             e['gw_ip']), "end"])
            sendp(pkt, iface=conf.iface)
            time.sleep(1)
        results = helper.parse_dhcp_pool_show(evpn)
        if (not helper.array_value_exits(results['Declined IP addresses'], ip)):
            print("\tIP %s did not get Declined" % ip)
            assert(0)
        else:
            print("\tIP %s did get Declined" % ip)
            return True
            """
