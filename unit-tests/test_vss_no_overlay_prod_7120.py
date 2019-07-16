#!/usr/bin/python
import sys
import os
import time
import json
import subprocess
from pprint import pprint
import netns
import logging
import pytest
import helper
import re
import multiprocessing
import ipaddr
import random
from threading import Thread

import xml.etree.ElementTree as ET
sys.path.append('../config')
reload(sys)
from helper import *

ovs = ovs_class('../config/vss_no_overlay_config.json', 16 , 2)
vdf_uplink="eth0"

def pytest_generate_tests(metafunc):
    idlist = []
    argvalues = []
    if (metafunc.function.__name__ == 'test_vdf_uplink_creation_deletion_on_evpn_events'
        or metafunc.function.__name__ == 'test_kill_ovs_vdf_uplink_verfication'
        or metafunc.function.__name__ == 'test_subnet_vlan_flood_flag_post_cleanup'):
       for evpn_id in ovs.evpns:
           logging.info(evpn_id)
           if ovs.evpn_flag_enabled(evpn_id, "l3_proxy"):
              argvalues.append([evpn_id])
       metafunc.parametrize(metafunc.fixturenames, argvalues)
    elif (metafunc.function.__name__ == 'test_flow_trace_same_subnet'
          or metafunc.function.__name__ == 'test_pre_pg_acl_same_subnet'
          or metafunc.function.__name__ == 'test_post_pg_acl_same_subnet'):
       for evpn_id in ovs.evpns:
           if not ovs.evpn_flag_enabled(evpn_id, "l3_proxy"):
              continue
           allvms = ovs.evpns[evpn_id]['vms']
           args = list(itertools.product(allvms, allvms))
           for i in args:
               if i[0] != i[1]:
                  argvalues.append(i)
       metafunc.parametrize(metafunc.fixturenames, argvalues)
    elif (metafunc.function.__name__ == 'test_flow_trace_different_subnet'
          or metafunc.function.__name__ == 'test_pre_pg_acl_different_subnet'
          or metafunc.function.__name__ == 'test_post_pg_acl_different_subnet'):
       for vrf_id in ovs.vrfs:
           allevpns = []
           for evpn_id in ovs.vrfs[vrf_id]['evpns']:
               if not ovs.evpn_flag_enabled(evpn_id, "l3_proxy"):
                  continue
               allevpns.append(evpn_id)
           args = list(itertools.product(allevpns, allevpns))
           for i in args:
               if i[0] != i[1]:
                  allAvms = ovs.evpns[i[0]]['vms']
                  allBvms = ovs.evpns[i[1]]['vms']
                  vmargs = list(itertools.product(allAvms, allBvms))
           for i in vmargs:
               if i[0] != i[1]:
                  argvalues.append(i)
       metafunc.parametrize(metafunc.fixturenames, argvalues)
    elif (metafunc.function.__name__ == 'test_gw_mac_learning'
         or metafunc.function.__name__ == 'test_flow_trace_same_subnet_remote'
         or metafunc.function.__name__ == 'test_arp_to_n_from_gw'):
       for evpn_id in ovs.evpns:
           if not ovs.evpn_flag_enabled(evpn_id, "l3_proxy"):
              continue
           allvms = ovs.evpns[evpn_id]['vms']
           for i in allvms:
               argvalues.append([i])
       metafunc.parametrize(metafunc.fixturenames, argvalues)
def setup_module():
    """
    ovs.cleanup()
    ovs.ns_reinit()
    """
    ovs.ovs_restart()
    ovs.vm_port_setup()
    """
    ovs.ns_vm_dhcp()
    """
    global flows_b4_setup
    flows_b4_setup = ovs.ovs_flows()
    logging.info("Number of flows at module setup: %d" % len(flows_b4_setup))

def teardown_module():
    """
    ovs.cleanup()
    """
    logging.info("\nTearing Down Module ...")
"""
@pytest.mark.parametrize("evpn", [
            (11), (12), (21), (22), (41), (42), (51), (52),
            ])
"""
@pytest.mark.last
def test_vdf_uplink_creation_deletion_on_evpn_events(evpn):
    if not ovs.evpn_flag_enabled(evpn, "l3_proxy"):
       logging.warn("evpn 0x%x not l3-proxy" % evpn)
       return
    for i in range(5):
        vdf_evpn_uplink = 'sv-'+vdf_uplink+'.'\
                          +str(ovs.evpns[int(evpn)]['properties']['vni_id'])
        assert (ovs.ovsrec_present_in_ovsdb("Interface", "name", vdf_evpn_uplink)
                and ovs.ovs_check_port_exists(vdf_evpn_uplink)),\
              ("Expected %s not created, for evpn: 0x%x"\
               % (vdf_evpn_uplink, int(evpn)))
        ovs.evpn_delete(evpn)
        assert (not ovs.ovsrec_present_in_ovsdb("Interface", "name", vdf_evpn_uplink)
                and not ovs.ovs_check_port_exists(vdf_evpn_uplink)),\
              ("Expected %s not deleted, for evpn: 0x%x"\
               % (vdf_evpn_uplink, int(evpn)))
        ovs.evpn_create(evpn)
        time.sleep(5)
        assert (ovs.ovsrec_present_in_ovsdb("Interface", "name", vdf_evpn_uplink)
                and ovs.ovs_check_port_exists(vdf_evpn_uplink)),\
              ("Expected %s not created, for evpn: 0x%x"\
               % (vdf_evpn_uplink, int(evpn)))

"""
1. create-evpn1  let ofport be 5001
2. delete-evpn1  free 5001
3. create-evpn2  reassign 5001
4. create-evpn1  should get assign new ofport for vdf uplink
"""
@pytest.mark.parametrize("vrf, evpn1, evpn2", [
                         (1, 11, 12),
                         ])
@pytest.mark.last
def test_vdf_uplink_ofport_reassigning(vrf, evpn1, evpn2):
    pid = ovs.ovs_get_pid()
    ovs.evpn_delete(evpn1)
    ovs.evpn_create(evpn1)
    time.sleep(5)
    vdf_evpn_uplink = 'sv-'+vdf_uplink+'.'\
                      +str(ovs.evpns[int(evpn1)]['properties']['vni_id'])
    curr_pid = ovs.ovs_get_pid()
    assert pid == curr_pid and ovs.ovs_check_port_exists(vdf_evpn_uplink),\
          ("Expected %s not created, for evpn: 0x%x"\
           % (vdf_evpn_uplink, (int(evpn1))))

    ovs.evpn_delete(evpn1)
    curr_pid = ovs.ovs_get_pid()
    assert pid == curr_pid and not ovs.ovs_check_port_exists(vdf_evpn_uplink),\
          ("Expected %s not deleted, for evpn: 0x%x"\
           % (vdf_evpn_uplink, (int(evpn1))))

    ovs.evpn_create(evpn2)
    time.sleep(5)
    vdf_evpn_uplink = 'sv-'+vdf_uplink+'.'\
                      +str(ovs.evpns[int(evpn2)]['properties']['vni_id'])
    curr_pid = ovs.ovs_get_pid()
    assert pid == curr_pid and ovs.ovs_check_port_exists(vdf_evpn_uplink),\
          ("Expected %s not created, for evpn: 0x%x"\
           % (vdf_evpn_uplink, int(evpn2)))
    ovs.evpn_create(evpn1)
    time.sleep(5)
    vdf_evpn_uplink = 'sv-'+vdf_uplink+'.'\
                      +str(ovs.evpns[int(evpn1)]['properties']['vni_id'])
    curr_pid = ovs.ovs_get_pid()
    assert pid == curr_pid and ovs.ovs_check_port_exists(vdf_evpn_uplink),\
          ("Expected %s not created, for evpn: 0x%x"\
           % (vdf_evpn_uplink, hex(int(evpn1))))

def config_remote_vm_routes(vrf, evpn, vm_ip, vm_mac):
    ovs.add_remote_vm_route(vrf, evpn, vm_ip, vm_mac)
    vrf_rule = ovs.ovs_find_rule(('vrf_id=0x%x,ip,reg17=0x1000000/0x1000000,nw_dst=%s' % (vrf, vm_ip)))
    assert(vrf_rule != None)
    logging.debug(vrf_rule)
    arp_rule = ovs.ovs_find_rule(('vrf_id=0x%x,evpn_id=0x%x,ip,nw_dst=%s' % (vrf, evpn, vm_ip)))
    assert(arp_rule != None)
    logging.debug(arp_rule)
    mac_rule = ovs.ovs_find_rule(('vrf_id=0x%x,evpn_id=0x%x,dl_dst=%s' % (vrf, evpn, vm_mac)))
    assert(mac_rule != None)
    mac_rule_actions = mac_rule.split('actions=')[1]
    vdf_evpn_uplink = 'sv-'+vdf_uplink+'.'\
                      +str(ovs.evpns[int(evpn)]['properties']['vni_id'])
    p = ovs.ovs_get_port(vdf_evpn_uplink);
    assert(p != None)
    exp_output_action = ('output:%d' % int(p[0]))
    p[0] = 65526
    exp_output_action = ('%d' % int(p[0]))
    logging.debug(mac_rule)
    assert exp_output_action in mac_rule_actions,\
           "Mac rule was not with vdf uplink output"
"""
@pytest.mark.parametrize("src, dst", [
                         ("vm1", "vm9"),
                         ("vm9", "vm1"),
                         ("vm6", "vm14"),
                         ("vm14", "vm6"),
                         ])
"""
def test_flow_trace_same_subnet(src, dst, pg_acl=False):
    src_dp_port = ovs.ovs_get_port(src)[1];
    dst_dp_port = ovs.ovs_get_port(dst)[1];
    src_ip = ovs.vms[src]['ip']
    src_mac = ovs.vms[src]['mac']
    dst_ip = ovs.vms[dst]['ip']
    dst_mac = ovs.vms[dst]['mac']

    if pg_acl :
       ovs.pg_acl('add', src, ovs.vms[src]['uuid'], str(ovs.vms[dst]['evpn']), 'pre', 'deny')
    flow = ("recirc_id(0),dp_hash(0),skb_priority(0),in_port(%s),skb_mark(0),"\
            "eth(src=%s,dst=%s),eth_type(0x0800),ipv4(src=%s,dst=%s,proto=1,"\
            "tos=0,ttl=64,frag=no),icmp(type=0,code=0)"\
            % (src_dp_port, src_mac, dst_mac, src_ip, dst_ip))

    ovs_flows_trace = ovs.ovs_trace(flow)
    if pg_acl:
        assert('drop' in ovs_flows_trace['Datapath actions:'])
        ovs.pg_acl('add', src, ovs.vms[src]['uuid'], str(ovs.vms[dst]['evpn']),
                   'pre', 'allow')
        ovs_flows_trace = ovs.ovs_trace(flow)
        ovs.pg_acl('delete', src, ovs.vms[src]['uuid'], str(ovs.vms[dst]['evpn']),
                   'pre', 'allow')
        ovs.pg_acl('add', src, ovs.vms[src]['uuid'], str(ovs.vms[dst]['evpn']),
                   'all', 'allow')
    assert(dst_dp_port in ovs_flows_trace['Datapath actions:'])
    NetworkUtil.send_icmp(src.split('-')[0], src_mac, dst_mac, src_ip, dst_ip)

def test_pre_pg_acl_different_subnet(src, dst):
    test_flow_trace_different_subnet(src, dst, True)

def test_pre_pg_acl_same_subnet(src, dst):
    test_flow_trace_same_subnet(src, dst, True)

"""
@pytest.mark.parametrize("src", [
                         ("vm1-veth1")
                         ])
"""
def test_flow_trace_same_subnet_remote(src):
    evpn = ovs.vms[src]['evpn']
    vrf = ovs.vms[src]['vrf']
    src_dp_port = ovs.ovs_get_port(src)[1];
    src_ip = ovs.vms[src]['ip']
    src_mac = ovs.vms[src]['mac']
    vdf_evpn_uplink = 'sv-'+vdf_uplink+'.'\
                      +str(ovs.evpns[evpn]['properties']['vni_id'])
    dst_dp_port = ovs.ovs_get_port(vdf_evpn_uplink)[1];

    subnet= ovs.evpns[evpn]['properties']['subnet']
    mask = ovs.evpns[evpn]['properties']['mask']
    random_dst_ip = NetworkUtil.getRandomIP(subnet, mask)
    random_dst_mac = randomMAC()
    config_remote_vm_routes(vrf, evpn, random_dst_ip, random_dst_mac)
    # 1. VM to remote ip, should go thr vlan uplink
    flow = ("recirc_id(0),dp_hash(0),skb_priority(0),in_port(%s),skb_mark(0),"\
            "eth(src=%s,dst=%s),eth_type(0x0800),ipv4(src=%s,dst=%s,proto=1,"\
            "tos=0,ttl=64,frag=no),icmp(type=0,code=0)"\
            % (src_dp_port, src_mac, random_dst_mac, src_ip, random_dst_ip))

    ovs_flows_trace = ovs.ovs_trace(flow)
    assert(dst_dp_port in ovs_flows_trace['Datapath actions:'])

    # 2. vlan uplink to vm coming in from remote ovs
    flow = ("recirc_id(0),dp_hash(0),skb_priority(0),in_port(%s),skb_mark(0),"\
            "eth(src=%s,dst=%s),eth_type(0x0800),ipv4(src=%s,dst=%s,proto=1,"\
            "tos=0,ttl=64,frag=no),icmp(type=0,code=0)"\
            % (dst_dp_port, random_dst_mac, src_mac, random_dst_ip, src_ip))
    ovs_flows_trace = ovs.ovs_trace(flow)
    assert(src_dp_port in ovs_flows_trace['Datapath actions:'])

    # 3. vlan uplink to remote vm coming in from remote ovs
    flow = ("recirc_id(0),dp_hash(0),skb_priority(0),in_port(%s),skb_mark(0),"\
            "eth(src=%s,dst=%s),eth_type(0x0800),ipv4(src=%s,dst=%s,proto=1,"\
            "tos=0,ttl=64,frag=no),icmp(type=0,code=0)"\
            % (dst_dp_port, src_mac, random_dst_mac, src_ip, random_dst_ip))

    ovs_flows_trace = ovs.ovs_trace(flow)
    assert('drop' in ovs_flows_trace['Datapath actions:'])


def refresh_vdf_gw_ip_arp(src):
    evpn = ovs.vms[src]['evpn']
    vrf = ovs.vms[src]['vrf']
    vdf_evpn_uplink = 'sv-'+vdf_uplink+'.'\
                      +str(ovs.evpns[evpn]['properties']['vni_id'])
    vdf_uplink_port = ovs.ovs_get_port(vdf_evpn_uplink);
    src_port = ovs.ovs_get_port(src);
    src_ip = ovs.vms[src]['ip']
    gw_ip = ovs.evpns[evpn]['properties']['gw_ip']
    src_mac = NetworkUtil.getHwAddr(vdf_evpn_uplink)
    logging.info("Refreshing ARP entry with %s(%s) for %s ..."\
                 % (gw_ip, src_mac, src))
    pkt = NetworkUtil.compose_arp_reply(gw_ip, src_ip, src_mac)
    ovs.send_pkt_out(vdf_uplink_port[0], src_port[0], str(pkt).encode("HEX"))
"""
@pytest.mark.parametrize("src", [
                         ("vm1"), ("vm2"), ("vm3"), ("vm4"), ("vm5"), ("vm6"), ("vm7"), ("vm8"),
                         ])
"""
def test_gw_mac_learning(src):
    evpn = ovs.vms[src]['evpn']
    vrf = ovs.vms[src]['vrf']
    vdf_evpn_uplink = 'sv-'+vdf_uplink+'.'\
                      +str(ovs.evpns[evpn]['properties']['vni_id'])
    vdf_uplink_port = ovs.ovs_get_port(vdf_evpn_uplink);
    src_port = ovs.ovs_get_port(src);
    src_ip = ovs.vms[src]['ip']
    gw_ip = ovs.evpns[evpn]['properties']['gw_ip']
    src_mac = NetworkUtil.getHwAddr(vdf_evpn_uplink)

    refresh_vdf_gw_ip_arp(src)

    rule = ovs.ovs_find_rule('vrf_id=0x%x,evpn_id=0x%x,dl_dst=%s'\
                             %(int(vrf), int(evpn), src_mac))
    rule_actions = rule.split('actions=')[1]
    exp_output_action = ('output:%d' % int(vdf_uplink_port[0]))
    assert exp_output_action in rule_actions,\
           "Mac rule was not with vdf uplink output"
    logging.info("Leart-mac rule: %s" % rule)
"""
@pytest.mark.parametrize("src, dst", [
                         ("vm1", "vm3"),
                         ("vm3", "vm1"),
                         ("vm9", "vm11"),
                         ("vm11", "vm9"),
                         ])
"""
def test_flow_trace_different_subnet(src, dst, pg_acl=False):
    src_dp_port = ovs.ovs_get_port(src)[1];
    src_ip = ovs.vms[src]['ip']
    src_mac = ovs.vms[src]['mac']
    dst_ip = ovs.vms[dst]['ip']
    evpn = ovs.vms[src]['evpn']
    vdf_evpn_uplink = 'sv-'+vdf_uplink+'.'\
                      +str(ovs.evpns[evpn]['properties']['vni_id'])
    dst_dp_port = ovs.ovs_get_port(vdf_evpn_uplink)[1];
    dst_mac = NetworkUtil.getHwAddr(vdf_evpn_uplink)

    if pg_acl :
       ovs.pg_acl('add', src, ovs.vms[src]['uuid'], str(ovs.vms[dst]['evpn']), 'pre', 'deny')
    #1: src to tagged vdf interface
    flow = ("recirc_id(0),dp_hash(0),skb_priority(0),in_port(%s),skb_mark(0),"\
            "eth(src=%s,dst=%s),eth_type(0x0800),ipv4(src=%s,dst=%s,proto=1,"\
            "tos=0,ttl=64,frag=no),icmp(type=0,code=0)"\
            % (src_dp_port, src_mac, dst_mac, src_ip, dst_ip))
    refresh_vdf_gw_ip_arp(src)
    ovs_flows_trace = ovs.ovs_trace(flow)
    assert(13 in ovs_flows_trace['ovs_pipeline']),\
           "flow missed VRF_TABLE lookup"
    if pg_acl:
        logging.info("Table 9  ACL Rule: %s" % ovs_flows_trace[9])
        assert('drop' in ovs_flows_trace['Datapath actions:'])
    else :
        assert(dst_dp_port in ovs_flows_trace['Datapath actions:'])

    #2: TOR will do the vlan switching
    # testing dst vdf-uplink to dst vm
    evpn = ovs.vms[dst]['evpn']
    vdf_evpn_uplink = 'sv-'+vdf_uplink+'.'\
                      +str(ovs.evpns[evpn]['properties']['vni_id'])
    src_dp_port = ovs.ovs_get_port(vdf_evpn_uplink)[1];
    src_mac = NetworkUtil.getHwAddr(vdf_evpn_uplink)
    dst_mac = ovs.vms[dst]['mac']
    dst_dp_port = ovs.ovs_get_port(dst)[1];
    if pg_acl :
       ovs.pg_acl('add', src, ovs.vms[src]['uuid'], str(ovs.vms[dst]['evpn']),
                  'pre', 'allow')
    flow = ("recirc_id(0),dp_hash(0),skb_priority(0),in_port(%s),skb_mark(0),"\
            "eth(src=%s,dst=%s),eth_type(0x0800),ipv4(src=%s,dst=%s,proto=1,"\
            "tos=0,ttl=63,frag=no),icmp(type=0,code=0)"\
            % (src_dp_port, src_mac, dst_mac, src_ip, dst_ip))
    ovs_flows_trace = ovs.ovs_trace(flow)
    if pg_acl:
        """
        assert('drop' in ovs_flows_trace['Datapath actions:'])
        ovs.pg_acl('add', src, ovs.vms[src]['uuid'], str(ovs.vms[dst]['evpn']),
                   'pre', 'allow')
        ovs.pg_acl('delete', src, ovs.vms[src]['uuid'], str(ovs.vms[dst]['evpn']),
                   'pre', 'allow')
        """
        ovs.pg_acl('add', src, ovs.vms[src]['uuid'], str(ovs.vms[dst]['evpn']),
                   'all', 'allow')
        ovs_flows_trace = ovs.ovs_trace(flow)
    assert(dst_dp_port in ovs_flows_trace['Datapath actions:'])
    assert(13 not in ovs_flows_trace['ovs_pipeline']),\
           "flow unnecessary VRF_TABLE lookup"
    assert(11 in ovs_flows_trace['ovs_pipeline']),\
           "flow missed EVPN_MAC_TABLE lookup"

@pytest.mark.skip(reason="no way of currently testing this")
@pytest.mark.parametrize("vrf_id", [
            (1),
            ])
def test_e2e_evpn_events(vrf_id):
    new_evpns = []
    for evpn_id in ovs.vrfs[vrf_id]['evpns']:
        e = ovs.evpns[evpn_id]
        for i in range(1, 60):
            new_evpn_id = random.randint(500,4096)
            new_subnet = str(NetworkUtil.getRandomIP('0.0.0.0', '0.0.0.0'))
            new_subnetv6 = str(NetworkUtil.getRandomIP('::', '0', True))
            mask = e['properties']['mask']
            ovs.evpns[new_evpn_id] = e
            ovs.evpns[new_evpn_id]['properties']['evpn_id'] = new_evpn_id
            ovs.evpns[new_evpn_id]['properties']['vni_id'] = new_evpn_id
            ovs.evpns[new_evpn_id]['properties']['subnet'] = new_subnet
            ovs.evpns[new_evpn_id]['properties']['gw_ip'] = NetworkUtil.getRandomIP(new_subnet, mask)
            ovs.evpns[new_evpn_id]['properties']['gw_mac'] = randomMAC()

            #e['properties']['subnetv6'] = new_subnetv6
            #e['properties']['gw_ipv6'] = NetworkUtil.getRandomIP(new_subnetv6, '80')
            new_evpns.append(new_evpn_id)
    logging.info(new_evpns)
    for evpn_id in new_evpns:
        logging.info(ovs.evpns[evpn_id]['properties']['vni_id'])
        ovs.evpn_create(evpn_id)

    for evpn_id in new_evpns:
        vdf_evpn_uplink = 'sv-'+vdf_uplink+'.'\
                          +str(ovs.evpns[int(evpn_id)]['properties']['vni_id'])
        assert ovs.ovs_check_port_exists(vdf_evpn_uplink),\
              ("Expected %s not created, for evpn: 0x%x"\
               % (vdf_evpn_uplink, int(evpn_id)))

    for evpn_id in new_evpns:
        ovs.evpn_delete(evpn_id)
    for evpn_id in new_evpns:
        vdf_evpn_uplink = 'sv-'+vdf_uplink+'.'\
                          +str(ovs.evpns[int(evpn_id)]['properties']['vni_id'])
        assert not ovs.ovs_check_port_exists(vdf_evpn_uplink),\
              ("Expected %s not deleted, for evpn: 0x%x"\
               % (vdf_evpn_uplink, int(evpn_id)))

def test_subnet_vlan_flood_flag_post_cleanup(evpn):
    vdf_evpn_uplink = 'sv-'+vdf_uplink+'.'\
                      +str(ovs.evpns[int(evpn)]['properties']['vni_id'])

    r = exe(("ovs-appctl evpn/show alubr0 %d | grep %s"%\
             (int(evpn), vdf_evpn_uplink)))
    assert not r[0]
    output = r[1].split()
    logging.info(output)
    assert ('yes' in output),\
           ("Flood flag not set for evpn 0x%x, %s"% (evpn, vdf_evpn_uplink))

    ovs.ovs_bump_gen_id()
    ovs.vm_port_setup()
    ovs.ovs_cleanup()

    r = exe(("ovs-appctl evpn/show alubr0 %d | grep %s"%\
            (int(evpn), vdf_evpn_uplink)))
    assert not r[0]
    output = r[1].split()
    logging.info(output)
    assert ('yes' in output),\
           ("Flood flag not set for evpn 0x%x, %s"% (evpn, vdf_evpn_uplink))

"""
1. get subnet uplink for evpn1
2. kill ovs with signal 6
3. add-vrf 1
4. add-evpn evpn1
5. subnet uplink for evpn1 should match earlier value
6. delete-evpn subnet uplink should get deleted
"""
"""
@pytest.mark.parametrize("evpn", [
                         (11),
                         ])
"""
@pytest.mark.last
def test_kill_ovs_vdf_uplink_verfication(evpn):
    logging.info("vrf : %s" % ovs.evpns[evpn]['vrf'])
    vrf = int(ovs.evpns[evpn]['vrf'])
    vdf_evpn_uplink = 'sv-'+vdf_uplink+'.'\
                      +str(ovs.evpns[int(evpn)]['properties']['vni_id'])
    ovs_user_port = ovs.ovs_get_port(vdf_evpn_uplink);
    pid = ovs.ovs_get_pid()
    exe(("kill -6 %d" % pid))
    logging.info("killing ovs-vswitchd pid %d" % pid)
    time.sleep(5)
    pid = ovs.ovs_get_pid()
    logging.info("ovs-vswitchd new pid %d" % pid)
    ovs.vrf_create(vrf)
    ovs.evpn_create(evpn)
    new_ovs_user_port = ovs.ovs_get_port(vdf_evpn_uplink);
    assert new_ovs_user_port == ovs_user_port ,\
           ("%s Expected %d,  Actual %d"\
            % (vdf_evpn_uplink, ovs_user_port, new_ovs_user_port))
    ovs.evpn_delete(evpn)
    time.sleep(5)
    assert (not ovs.ovs_check_port_exists(vdf_evpn_uplink)),\
          ("Expected %s not deleted, for evpn: 0x%x"\
           % (vdf_evpn_uplink, int(evpn)))
    ovs.vm_port_setup()

"""
@pytest.mark.parametrize("src", [
                         ("vm1-veth1"),
                         ])
"""
def test_arp_to_n_from_gw(src):
    test_gw_mac_learning(src)
    evpn = ovs.vms[src]['evpn']
    gw_ip = ovs.evpns[evpn]['properties']['gw_ip']

    vdf_evpn_uplink = 'sv-'+vdf_uplink+'.'\
                      +str(ovs.evpns[evpn]['properties']['vni_id'])
    vdf_uplink_port = ovs.ovs_get_port(vdf_evpn_uplink)[1]
    vdf_uplink_port_mac = NetworkUtil.getHwAddr(vdf_evpn_uplink)
    src_port = ovs.ovs_get_port(src)[1]
    src_mac = ovs.vms[src]['mac']
    src_ip = ovs.vms[src]['ip']
    #1. ARP to gw from vm
    flow=("recirc_id(0),dp_hash(0),skb_priority(0),in_port(%d),"\
          "eth(src=%s,dst=%s),"\
          "eth_type(0x0806),arp(sip=%s,tip=%s,"\
          "op=2/0xff,sha=%s,tha=%s)"\
          % (int(src_port), src_mac, vdf_uplink_port_mac,
             src_ip, gw_ip, src_mac, vdf_uplink_port_mac))
    ovs_flows_trace = ovs.ovs_trace(flow)
    assert(11 in ovs_flows_trace['ovs_pipeline']),\
           "flow missed MAC_TABLE lookup"
    assert(vdf_uplink_port in ovs_flows_trace['Datapath actions:'])
    #2. ARP from gw to vm
    flow=("recirc_id(0),dp_hash(0),skb_priority(0),in_port(%d),"\
          "eth(src=%s,dst=%s),"\
          "eth_type(0x0806),arp(sip=%s,tip=%s,"\
          "op=1/0xff,sha=%s,tha=%s)"\
          % (int(vdf_uplink_port), vdf_uplink_port_mac, "ff:ff:ff:ff:ff:ff",
             gw_ip, src_ip, vdf_uplink_port_mac, "00:00:00:00:00:00"))
    ovs_flows_trace = ovs.ovs_trace(flow)
    assert(11 in ovs_flows_trace['ovs_pipeline']),\
           "flow missed MAC_TABLE lookup"
    assert(src_port in ovs_flows_trace['Datapath actions:'])
"""
@pytest.mark.parametrize("src, dst", [
                         ("vm8-veth1", "vm14-veth1"),
                         ])
"""
def post_pg_acl(src, dst):
    dst_dp_port = ovs.ovs_get_port(dst)[1];
    src_ip = ovs.vms[src]['ip']
    src_mac = ovs.vms[src]['mac']
    dst_ip = ovs.vms[dst]['ip']
    dst_mac = ovs.vms[dst]['mac']

    src_evpn = ovs.vms[src]['evpn']
    vdf_evpn_uplink = 'sv-'+vdf_uplink+'.'\
                      +str(ovs.evpns[src_evpn]['properties']['vni_id'])
    src_mac = NetworkUtil.getHwAddr(vdf_evpn_uplink)

    dst_evpn = ovs.vms[dst]['evpn']
    vdf_evpn_uplink = 'sv-'+vdf_uplink+'.'\
                      +str(ovs.evpns[dst_evpn]['properties']['vni_id'])
    src_dp_port = ovs.ovs_get_port(vdf_evpn_uplink)[1];
    ovs.pg_acl('add', dst, ovs.vms[dst]['uuid'], str(ovs.vms[src]['evpn']),
               'post', 'deny')

    flow = ("recirc_id(0),dp_hash(0),skb_priority(0),in_port(%s),skb_mark(0),"\
            "eth(src=%s,dst=%s),eth_type(0x0800),ipv4(src=%s,dst=%s,proto=1,"\
            "tos=0,ttl=64,frag=no),icmp(type=0,code=0)"\
            % (src_dp_port, src_mac, dst_mac, src_ip, dst_ip))

    ovs_flows_trace = ovs.ovs_trace(flow)
    assert('drop' in ovs_flows_trace['Datapath actions:'])
def test_post_pg_acl_different_subnet(src, dst):
    post_pg_acl(src, dst)
def test_post_pg_acl_same_subnet(src, dst):
    post_pg_acl(src, dst)
@pytest.mark.skip(reason="no way of currently testing this")
def test_evpns():
    for i in range(20):
        if i%2 == 0:
           ovs.evpn_delete("12")
           ovs.evpn_create("11")
           ovs.evpn_delete("21")
        else :
           ovs.evpn_create("12")
           ovs.evpn_delete("11")
           ovs.evpn_create("21")

def looper(f, args, count = 1):
    logging.basicConfig(format='', level=logging.WARN)
    logging.info("Looper: %s(%s): %d" % (f, args, count))
    for i in range(count):
        #logging.info("Looper: %d" % i)
        time.sleep(1)
        f(args)
        #logging.info("Looper: %d done" % i)
@pytest.mark.skip(reason="no way of currently testing this")
@pytest.mark.parametrize("src", [
                         ("vm1-veth1")
                         ])
def test_events_thread(src):
    pid = ovs.ovs_get_pid()
    t1 = Thread(target=looper, args=(test_flow_trace_same_subnet_remote,src,100))
    t2 = Thread(target=looper, args=(test_arp_to_n_from_gw,src,100))
    t3 = Thread(target=looper, args=(test_gw_mac_learning,src,100))
    t4 = Thread(target=looper, args=(test_flow_trace_same_subnet_remote,"vm2-veth1",100))
    t1.start()
    t2.start()
    t3.start()
    t4.start()
    ovs.ovs_bump_gen_id()
    time.sleep(10)
    ovs.ovs_cleanup()
    ovs.vm_port_setup()
    time.sleep(10)
    t1.join(200.0)
    t2.join(200.0)
    t3.join(200.0)
    t4.join(200.0)
    assert(pid == ovs.ovs_get_pid())
