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

import xml.etree.ElementTree as ET
sys.path.append('../config')
reload(sys)
from helper import *

ovs = ovs_class('../config/config.json', 16 , 2)
VRF_LOOKUP_UE="ip,reg1=0x80000000/0x80000000,nw_dst=%s,actions=set_vrf_id:%s"
VRF_LOOKUP_UD="ip,reg1=0x0/0x80000000,nw_dst=%s,actions=set_vrf_id:%s"

def setup_module():
    """
    logging.info("\nSetup Module ...")
    exe('ip netns exec spat_ns sysctl net.ipv4.ip_forward=1')
    exe('ip netns exec spat_ns iptables -t nat -F')
    exe('ip netns exec spat_ns iptables -t mangle -F')
    global ovs_pid
    ovs_pid = helper.get_pid("ovs-vswitchd")
    logging.info("ovs-vswitchd pid : %d" % ovs_pid)

    ovs.ovs_bump_gen_id()
    ovs.ovs_cleanup()
    ovs.vm_port_setup()
    """
    ovs.ovs_restart()
    ovs.vm_port_setup()
    deleteAllBGP()
    global flows_b4_setup
    flows_b4_setup = ovs.ovs_flows()
    logging.info("Number of flows at module setup: %d" % len(flows_b4_setup))
    exe("/usr/bin/ovsdb-client transact '[\"Open_vSwitch\", {\"op\" : \"delete\", \"table\" : \"Nuage_Route\", \"where\" : [ ] } ]'")
    deleteAllBGP()

def teardown_module():
    exe("/usr/bin/ovsdb-client transact '[\"Open_vSwitch\", {\"op\" : \"delete\", \"table\" : \"Nuage_Route\", \"where\" : [ ] } ]'")
    logging.info("\nTearing Down Module ...")

def deleteAllBGP():
    #cmd = "/usr/bin/ovsdb-client transact '[\"Open_vSwitch\", {\"op\" :\"delete\", \"table\" : \"Nuage_Route\", \"where\" : [[ \"route_owner\", \"==\", \"NuageBgp\" ]] } ]'"
    cmd = "/usr/bin/ovsdb-client transact '[\"Open_vSwitch\", {\"op\" : \"delete\", \"table\" : \"Nuage_Route\", \"where\" : [ ] } ]'"
    exe(cmd)
    logging.info("Deleted all bgp routes ...")

def mod_bgp_route(cmd, prefix, vrf_id, evpn_id, nexthop="127.0.0.1"):
    logging.info("%s BGP RT vrf_id: %s, evpn_id: %s %s"
                     % (cmd, hex(int(vrf_id)), hex(int(evpn_id)), prefix))
    if cmd == "add" :
       cmd = ("/usr/bin/ovsdb-client transact '[\"Open_vSwitch\", \
             {\"op\" : \"insert\", \"table\" : \"Nuage_Route\" , \
             \"row\" : { \"nexthops\" : \"{\\\"ip\\\":\\\"%s\\\", \
             \\\"evpn_id\\\":\\\"%s\\\"}\",  \"prefix\": \"%s\", \
             \"route_owner\":\"NuageBgp\", \"vrf_id\": %s } } ]'"
             % (nexthop, evpn_id, prefix, vrf_id))
    elif cmd == "delete":
        cmd = ("/usr/bin/ovsdb-client transact '[\"Open_vSwitch\",\
               {\"op\" : \"delete\", \"table\" : \"Nuage_Route\", \
               \"where\" : [[ \"prefix\", \"==\", \"%s\" ],\
               [ \"vrf_id\", \"==\", %d ]] } ]'" % (prefix, int(vrf_id)))
    exe(cmd)

def mod_vrf_lookup_and_verify(cmd, prefix, vrf_id, evpn_id):
    is_del = False
    verify = False
    del_verify = False
    if cmd == 'delete':
       is_del = True
    elif cmd == 'verify':
       verify = True
    elif cmd == 'delete-verify':
       del_verify = True
       is_del = False

    if not verify and not del_verify:
       mod_bgp_route(cmd, prefix, vrf_id, evpn_id)
    if del_verify:
       ovs.expect_rule((VRF_LOOKUP_UE %(prefix, str(hex(int(vrf_id))))), False,\
                       "VRF-Lookup rule UnderlayEnabled")
       ovs.expect_rule((VRF_LOOKUP_UD %(prefix, str(hex(int(vrf_id))))), False,\
                       "VRF-Lookup rule UnderlayEnabled")
    elif 'underlay' in ovs.evpns[int(evpn_id)]['properties']['flags']:
       ovs.expect_rule((VRF_LOOKUP_UE %(prefix, str(hex(int(vrf_id))))), not is_del,\
                       "VRF-Lookup rule UnderlayEnabled")
    else:
       ovs.expect_rule((VRF_LOOKUP_UD %(prefix, str(hex(int(vrf_id))))), not is_del,\
                       "VRF-Lookup rule UnderlayDisabled")

@pytest.mark.parametrize("cmd,prefix,vrf_id,evpn_id", [
            ("add", "100.100.0.0/16", "1", "11"),
            ("delete", "100.100.0.0/16", "1", "11")
            ])
def test_update_bgp_routes(cmd, prefix, vrf_id, evpn_id):
    mod_vrf_lookup_and_verify(cmd, prefix, vrf_id, evpn_id)

@pytest.mark.parametrize("prefix,vrf_id,evpn_id", [
            ("100.100.0.0/16", "1", "11"),
            ("101.100.0.0/16", "1", "12"),
            ("102.100.0.0/16", "2", "21"),
            ("103.100.0.0/16", "2", "22"),
            ("104.100.0.0/16", "4", "41"),
            ("105.100.0.0/16", "4", "42")
            ])
def test_update_bgp_routes_ovs_restart_verify(prefix, vrf_id, evpn_id):
    mod_vrf_lookup_and_verify("add", prefix, vrf_id, evpn_id)
    ovs.ovs_restart();
    ovs.vm_port_setup()
    mod_vrf_lookup_and_verify("verify", prefix, vrf_id, evpn_id)

@pytest.mark.parametrize("vrf_id,evpn_id", [
            ("1", "11"),
            ("1", "12"),
            ("2", "21"),
            ("2", "22")
            ])
def test_evpn_flag_updates_evpn_routes(vrf_id, evpn_id):
    evpn_subnet = ovs.evpns[int(evpn_id)]['properties']['subnet']+'/'+\
                 ovs.netmask_to_nbits(ovs.evpns[int(evpn_id)]['properties']['mask'])

    ovs.evpn_mod_flag(evpn_id, 'underlay', False)
    mod_vrf_lookup_and_verify('verify', evpn_subnet, vrf_id, evpn_id)

    ovs.evpn_mod_flag(evpn_id, 'underlay', True)
    mod_vrf_lookup_and_verify('verify', evpn_subnet, vrf_id, evpn_id)

    ovs.evpn_mod_flag(evpn_id, 'underlay', False)
    mod_vrf_lookup_and_verify('verify', evpn_subnet, vrf_id, evpn_id)

    ovs.evpn_mod_flag(evpn_id, 'underlay', True)
    mod_vrf_lookup_and_verify('verify', evpn_subnet, vrf_id, evpn_id)

@pytest.mark.parametrize("prefix,vrf_id,evpn_id", [
            ("100.100.0.0/16", "1", "11"),
            ("101.100.0.0/16", "1", "12"),
            ("102.100.0.0/16", "2", "21"),
            ("103.100.0.0/16", "2", "22"),
            ("104.100.0.0/16", "4", "41"),
            ("105.100.0.0/16", "4", "42")
            ])
def test_evpn_flag_updates_bgp_routes(prefix, vrf_id, evpn_id):
    ovs.evpn_mod_flag(evpn_id, 'underlay', True)
    mod_vrf_lookup_and_verify("add", prefix, vrf_id, evpn_id)

    ovs.evpn_mod_flag(evpn_id, 'underlay', False)
    mod_vrf_lookup_and_verify('verify', prefix, vrf_id, evpn_id)

    ovs.evpn_mod_flag(evpn_id, 'underlay', True)
    mod_vrf_lookup_and_verify('verify', prefix, vrf_id, evpn_id)

    ovs.evpn_mod_flag(evpn_id, 'underlay', False)
    mod_vrf_lookup_and_verify('verify', prefix, vrf_id, evpn_id)

@pytest.mark.parametrize("prefix,vm,vrf_id,evpn_id", [
            ("200.100.0.0/16", "vm1-veth1", "1", "11"),
            ("201.100.0.0/16", "vm3-veth1", "1", "12"),
            ("202.100.0.0/16", "vm2-veth1", "2", "21"),
            ("203.100.0.0/16", "vm4-veth1", "2", "22"),
            ("204.100.0.0/16", "vm5-veth1", "4", "41"),
            ("205.100.0.0/16", "vm7-veth1", "4", "42"),
            ("206.100.0.0/16", "vm6-veth1", "5", "51"),
            ("207.100.0.0/16", "vm8-veth1", "5", "52"),
            ])
def test_evpn_flag_updates_local_static_routes (prefix, vm, vrf_id, evpn_id):
    ovs.local_static_route(prefix, vm, vrf_id)
    ovs.evpn_mod_flag(evpn_id, 'underlay', True)
    mod_vrf_lookup_and_verify("verify", prefix, vrf_id, evpn_id)

    ovs.evpn_mod_flag(evpn_id, 'underlay', False)
    mod_vrf_lookup_and_verify('verify', prefix, vrf_id, evpn_id)

    ovs.evpn_mod_flag(evpn_id, 'underlay', True)
    mod_vrf_lookup_and_verify('verify', prefix, vrf_id, evpn_id)

    ovs.evpn_mod_flag(evpn_id, 'underlay', False)
    mod_vrf_lookup_and_verify('verify', prefix, vrf_id, evpn_id)

@pytest.mark.parametrize("prefix,vrf_id,evpn_id", [
            ("100.100.0.0/16", "1", "11"),
            ("102.100.0.0/16", "2", "21"),
            ("103.100.0.0/16", "2", "22"),
            ("104.100.0.0/16", "4", "41"),
            ("105.100.0.0/16", "4", "42")
            ])
def test_evpn_delete (prefix, vrf_id, evpn_id):
    evpn_subnet = ovs.evpns[int(evpn_id)]['properties']['subnet']+'/'+\
                 ovs.netmask_to_nbits(ovs.evpns[int(evpn_id)]['properties']['mask'])
    mod_vrf_lookup_and_verify("add", prefix, vrf_id, evpn_id)
    ovs.evpn_delete(evpn_id)
    mod_vrf_lookup_and_verify('delete-verify', evpn_subnet, vrf_id, evpn_id)
    mod_vrf_lookup_and_verify("delete-verify", prefix, vrf_id, evpn_id)
    ovs.evpn_mod_flag(evpn_id, 'dummy', False)

@pytest.mark.parametrize("vrf1, evpn1, vrf2, evpn2", [
            ("1", "11", "4", "41"),
            ("1", "12", "4", "42")
            ])
def test_evpn_flag_updates_evpn_routes_same_cidr(vrf1, evpn1, vrf2, evpn2):
    evpn_subnet1 = ovs.evpns[int(evpn1)]['properties']['subnet']+'/24'
    evpn_subnet2 = ovs.evpns[int(evpn2)]['properties']['subnet']+'/24'

    for f in [[True, True], [True, False], [False, True], [False, False]]:
        logging.info("evpn1 UE: %s, evpn2 UE: %s" % (f[0], f[1]))
        ovs.evpn_mod_flag(evpn1, 'underlay', f[0])
        ovs.evpn_mod_flag(evpn2, 'underlay', f[1])
        mod_vrf_lookup_and_verify('verify', evpn_subnet1, vrf1, evpn1)
        mod_vrf_lookup_and_verify('verify', evpn_subnet2, vrf2, evpn2)

@pytest.mark.parametrize("prefix,vrf_id,evpn_id", [
            ("100.100.0.0/16", "1", "11"),
            ("102.100.0.0/16", "2", "21"),
            ("103.100.0.0/16", "2", "22"),
            ("104.100.0.0/16", "4", "41"),
            ("105.100.0.0/16", "4", "42")
            ])
def test_crash (prefix, vrf_id, evpn_id):
    ovs.vm_port_setup()
    evpn_subnet = ovs.evpns[int(evpn_id)]['properties']['subnet']+'/'+\
                 ovs.netmask_to_nbits(ovs.evpns[int(evpn_id)]['properties']['mask'])
    ovs.evpn_mod_flag(evpn_id, 'underlay', True)

    mod_vrf_lookup_and_verify("delete", prefix, vrf_id, evpn_id)
    mod_vrf_lookup_and_verify("add", prefix, vrf_id, evpn_id)
    mod_vrf_lookup_and_verify('verify', evpn_subnet, vrf_id, evpn_id)

    ovs.evpn_delete(evpn_id)
    mod_vrf_lookup_and_verify("delete-verify", prefix, vrf_id, evpn_id)
    mod_vrf_lookup_and_verify('delete-verify', evpn_subnet, vrf_id, evpn_id)
    mod_vrf_lookup_and_verify("delete", prefix, vrf_id, evpn_id)

    ovs.evpn_mod_flag(evpn_id, 'dummy', False)
    ovs.evpn_mod_flag(evpn_id, 'underlay', True)
    mod_vrf_lookup_and_verify("add", prefix, vrf_id, evpn_id)
    mod_vrf_lookup_and_verify('verify', evpn_subnet, vrf_id, evpn_id)
