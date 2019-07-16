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
import multiprocessing
from scapy.all import *
import xml.etree.ElementTree as ET
sys.path.append('../config')
reload(sys)
from helper import *

ovs = OVS_setup('../config/config.json', 8 , 2)
def pytest_generate_tests(metafunc):
    for i in range (metafunc.config.option.count):
        metafunc.addcall()
    idlist = []
    argvalues = []
    global scenario
    scenario = ('all' if metafunc.config.option.all else 'basic')
    for i in ovs.evpns:
        e = ovs.evpns[i]
        if 'underlay' in e['properties']['flags']:
            for v in e['vms']:
                idlist.append(scenario +  " " + v + ", "+ovs.vms[v]['ip']\
                              +' => 135.227.176.180')
                argvalues.append(([v.split('-')[0], '135.227.176.180']))
    print metafunc.fixturenames
    metafunc.parametrize(metafunc.fixturenames, argvalues, ids=idlist)

def setup_module():
    ovs.fip_config('add')
def teardown_module():
    ovs.fip_config('delete')
def teardown_function():
    print("Associated fips ...")
    ovs.fip_config('add')
def setup_function():
    ovs.fip_ecmp_route_delete()
    print("Deleting fip ecmp routes...")

def test_fip_vrs_6949(ns_src, \
                      public_dst_ip):
    NetworkUtil.send_icmp(ns_src, ovs.vms[ns_src+'-veth1']['mac'],\
            ovs.evpns[ovs.vms[ns_src+'-veth1']['evpn']]['properties']['gw_mac'],\
            ovs.vms[ns_src+'-veth1']['ip'],\
            public_dst_ip)
    exe("ovs-dpctl dump-flows")

