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
#ovs = ovs_class('../config/config.json', 8 , 2)
cfg_file = '../config/config.json'
ovs = ovs_class(cfg_file, 50, 2, True)
ovs.ns_reinit()

def pytest_generate_tests(metafunc):
    for i in range (metafunc.config.option.count):
        metafunc.addcall()

def test_ovs_restarts():
    ovs.ovs_restart()
    assert(ovs.ovs_check_internal_ports())
    ovs.vm_port_setup()
    assert(ovs.ovs_check_internal_ports())

def test_ovs_stop_start():
    ovs.ovs_stop()
    ovs.ovs_start()
    assert(ovs.ovs_check_internal_ports())
    ovs.vm_port_setup()
    assert(ovs.ovs_check_internal_ports())
"""
def test_reinstall_ovs():
    exe('yum -y remove nuage-openvswitch nuage-openvswitch-kmod'\
        ' nuage-openvswitch-dkms nuage-openvswitch-debuginfo')
    cmd = 'rpm -ivh /root/nfs/ws/imgs/el7/nuage-openvswitch*'
    os.system(cmd)
    time.sleep(5)
    ovs.ovs_restart()
    ovs.vm_port_setup()
    assert(ovs.ovs_check_internal_ports())
"""
