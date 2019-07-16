#!/usr/bin/python
import sys
import os
import time
import json
import subprocess
from pprint import pprint
import netns
import logging
import helper
import multiprocessing
from scapy.all import *

sys.path.append('../config')
reload(sys)
from helper import *

ovs = ovs_class('../config/config.json', 16 , 2)
def setup_module():
    logging.debug("\n")

def teardown_module():
    logging.debug("\n")

def setup_function():
    logging.debug("\n")
    for ns in ['vm1', 'vm2', 'vm3', 'vm4' ]:
        cmd = 'ip netns exec '+ns+' ip neigh flush dev '+ns+'-veth0'
        logging.debug ("%s"% cmd)
        output = subprocess.check_output(cmd, shell=True)

def send_pkt_sniff(ns, pkt, sniff_filter= ''):
    logging.debug("\n"+ns+", pkt: %s" % pkt.command())
    ans = {}
    with netns.NetNS(nsname=ns):
        conf.verb=0
        conf.iface = ns+"-veth0"
        sendp(pkt, iface=conf.iface)
        if len(sniff_filter):
           ans=sniff(iface=ns+'-veth0', timeout=3, filter=sniff_filter)
    return ans
def nsma(a):
    n = inet_pton(socket.AF_INET6, a)
    return inet_ntop(socket.AF_INET6, in6_getnsma(n))
def nsmac(a):
    n = inet_pton(socket.AF_INET6, a)
    return in6_getnsmac(n)

# ethernet multicast address of solicited-node multicast address
def nsmamac(a):
    return nsmac(nsma(a))

def pytest_generate_tests(metafunc):
    if 'skip_gen' in metafunc.function.__name__:
       return
    idlist = []
    argvalues = []
    global scenario
    scenario = ('all' if metafunc.config.option.all else 'basic')

    if metafunc.function.__name__ == 'test_link_local_gw_ping_icmpv6' :
        for v in ovs.vms:
            if not ovs.vm_ipv6_enabled(v):
               continue
            vm = ovs.vms[v]
            idlist.append('%s' %(vm['interface']))
            argvalues.append(([vm['name']]))
    elif metafunc.function.__name__ == 'test_global_gw_ping_icmpv6' :
        for v in ovs.vms:
            if not ovs.vm_ipv6_enabled(v):
               continue
            vm = ovs.vms[v]
            #idlist.append(('%s, %s => %s'%(vm['interface'], vm['ipv6'], vm['gw_ipv6'])))
            idlist.append('%s'%(vm['interface']))
            argvalues.append(([vm]))
    elif metafunc.function.__name__ == 'test_router_solicitation_discovery' :
        for v in ovs.vms:
            if not ovs.vm_ipv6_enabled(v):
               continue
            vm = ovs.vms[v]
            idlist.append('%s' % (vm['interface']))
            argvalues.append(([vm['name']]))
    elif (metafunc.function.__name__ == 'test_global_same_subnet_traffic'
          or metafunc.function.__name__ == 'test_neighbor_solicitation_duplicate_addr_detection'
          or metafunc.function.__name__ == 'test_neighbor_solicitation_discovery'):
        for src_vm in ovs.vms:
            for dst_vm in ovs.vms:
                if src_vm == dst_vm:
                   continue;
                if not ovs.vm_ipv6_enabled(src_vm) or not ovs.vm_ipv6_enabled(dst_vm):
                    continue
                if ovs.vms[src_vm]['vrf'] != ovs.vms[dst_vm]['vrf']:
                    continue
                if ovs.vms[src_vm]['evpn'] != ovs.vms[dst_vm]['evpn']:
                    continue
                src = ovs.vms[src_vm]
                dst = ovs.vms[dst_vm]
                #idlist.append('%s, %s => %s '%(src_vm, src['ipv6'], dst['gw_ipv6']))
                idlist.append('%s => %s '%(src_vm, dst_vm))
                argvalues.append(([src_vm, dst_vm]))
    elif metafunc.function.__name__ == 'test_global_different_subnet_traffic':
        for src_vm in ovs.vms:
            for dst_vm in ovs.vms:
                if src_vm == dst_vm:
                   continue;
                if not ovs.vm_ipv6_enabled(src_vm) or not ovs.vm_ipv6_enabled(dst_vm):
                    continue
                if ovs.vms[src_vm]['vrf'] != ovs.vms[dst_vm]['vrf']:
                    continue
                if ovs.vms[src_vm]['evpn'] == ovs.vms[dst_vm]['evpn']:
                    continue
                src = ovs.vms[src_vm]
                dst = ovs.vms[dst_vm]
                idlist.append('%s => %s '%(src_vm, dst_vm))
                argvalues.append(([src_vm, dst_vm]))
    elif metafunc.function.__name__ == 'test_link_local_same_subnet_traffic':
        for src_vm in ovs.vms:
            for dst_vm in ovs.vms:
                if src_vm == dst_vm:
                   continue;
                if not ovs.vm_ipv6_enabled(src_vm) or not ovs.vm_ipv6_enabled(dst_vm):
                    continue
                if ovs.vms[src_vm]['vrf'] != ovs.vms[dst_vm]['vrf']:
                    continue
                if ovs.vms[src_vm]['evpn'] != ovs.vms[dst_vm]['evpn']:
                    continue
                src = ovs.vms[src_vm]
                dst = ovs.vms[dst_vm]
                idlist.append('%s => %s '%(src_vm, dst_vm))
                #idlist.append('%s, %s => %s '%(src_vm,\
                #        helper.mac_to_lla(src['mac']),\
                #        helper.mac_to_lla(dst['mac'])))
                argvalues.append(([src_vm, dst_vm]))

    metafunc.parametrize(metafunc.fixturenames, argvalues, ids=idlist)


def test_link_local_gw_ping_icmpv6(vm):
    vm = ovs.vms[vm]
    #logging.info("evpn: %s,  gw: %s" % ( str(ovs.evpns[vm['evpn']]), ovs.evpns[vm['evpn']]['properties']['gw_mac']))
    NetworkUtil.send_icmpv6_req(vm['name'].split('-')[0], vm['mac'],\
          '00:00:00:00:00:00', helper.mac_to_lla(vm['mac']),\
          helper.mac_to_lla(ovs.evpns[vm['evpn']]['properties']['gw_mac']), 5)

def test_global_gw_ping_icmpv6(vm):
        NetworkUtil.send_icmpv6_req(vm['name'].split('-')[0], vm['mac'],\
                '00:00:00:00:00:00',\
                vm['ipv6'], vm['gw_ipv6'], 2)

def test_router_solicitation_discovery(src):
    src_vm = ovs.vms[src]

    pkt = Ether(dst='33:33:ff:00:00:02', src=src_vm['mac'])/IPv6(src='::',\
                dst='ff02::2')/ICMPv6ND_RS()/\
                ICMPv6NDOptSrcLLAddr(lladdr=src_vm['mac'])
    ans = NetworkUtil.send_rcv(src.split('-')[0], pkt, 1, False)
    ra_found = len(ans)
    logging.info(ans.summary())
    """
    for a in ans:
        if a and a.type == ETH_P_IPV6 and \
           ipv6nh[a.payload.nh] == 'ICMPv6' and \
           icmp6types[a.payload.payload.type] == 'Router Advertisement':
           logging.debug("\nFound RA:=> %s" % a.command())
           ra_found = True
    """
    assert(ra_found), ("RA not in reply")

def test_neighbor_solicitation_discovery(src, dst):
    #src = 'vm3-veth1'
    #dst = 'vm1-veth1'
    src_vm = ovs.vms[src]
    dst_vm = ovs.vms[dst]

    nsm_dst_ipv6 = nsma(dst_vm['ipv6'])
    nsm_dst_mac = nsmamac(dst_vm['ipv6'])

    pkt = Ether(dst=nsm_dst_mac, src=src_vm['mac'])/IPv6(src=src_vm['ipv6'],\
                dst=nsm_dst_ipv6)/ICMPv6ND_NS(tgt=dst_vm['ipv6'])/\
                ICMPv6NDOptSrcLLAddr(lladdr=src_vm['mac'])
    ans = NetworkUtil.send_pkt_sniff(src.split('-')[0], pkt, 1, False,
             "ip6 and src "+dst_vm['ipv6']+" and dst "+src_vm['ipv6']+" and icmp6")
    ns_received = False
    for a in ans:
        if a and a.type == ETH_P_IPV6 and \
           ipv6nh[a.payload.nh] == 'ICMPv6' and \
           icmp6types[a.payload.payload.type] == 'Neighbor Advertisement':
           tgt=a.payload.payload.tgt
           logging.debug("\ntarget=%s" % (tgt))
           if tgt != dst_vm['ipv6']:
              assert(0)
           else:
              ns_received = True
              logging.debug("\nFound NS:=> %s" % a.command())
    assert(ns_received)

def test_neighbor_solicitation_duplicate_addr_detection(src, dst):
    src_vm = ovs.vms[src]
    dst_vm = ovs.vms[dst]

    nsm_dst_ipv6 = nsma(dst_vm['ipv6'])
    nsm_dst_mac = nsmamac(dst_vm['ipv6'])

    pkt = Ether(dst=nsm_dst_mac, src=src_vm['mac'])/IPv6(src='::',\
                dst='ff02::1')/ICMPv6ND_NS(tgt=dst_vm['ipv6'])
                #ICMPv6NDOptSrcLLAddr(lladdr=src_vm['mac'])
    ans = NetworkUtil.send_rcv(src.split('-')[0], pkt, 1, False)
                        # "ip6 and dst ff02::1 and icmp6")
    found = len(ans)
    for a in ans:
        if a and a.type == ETH_P_IPV6 and \
           ipv6nh[a.payload.nh] == 'ICMPv6' and \
           icmp6types[a.payload.payload.type] == 'Neighbor Advertisement':
           logging.debug("\nFound NS rsp :=> %s" % a.command())
           found = True
    assert(found)

def test_global_different_subnet_traffic(src_vm, dst_vm):
    src = ovs.vms[src_vm]
    dst = ovs.vms[dst_vm]
    NetworkUtil.send_icmpv6_req(src_vm.split('-')[0], src['mac'],\
               ovs.evpns[src['evpn']]['properties']['gw_mac'],\
               src['ipv6'], dst['ipv6'], 1)

def test_global_same_subnet_traffic(src_vm, dst_vm):
    src = ovs.vms[src_vm]
    dst = ovs.vms[dst_vm]
    NetworkUtil.send_icmpv6_req(src_vm.split('-')[0], src['mac'],\
          dst['mac'], src['ipv6'], dst['ipv6'], 1)

def test_link_local_same_subnet_traffic(src_vm, dst_vm):
    src = ovs.vms[src_vm]
    dst = ovs.vms[dst_vm]
    NetworkUtil.send_icmpv6_req(src_vm.split('-')[0], src['mac'], dst['mac'],\
                        helper.mac_to_lla(src['mac']),\
                        helper.mac_to_lla(dst['mac']), 1)
