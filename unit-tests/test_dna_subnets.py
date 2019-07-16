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

ovs = ovs_class('../config/config.json', 8 , 2)

@pytest.mark.parametrize("evpn_id", [
            (101),
            (102)
            ])
def test_config_proxy_arp_filter_list_dna_subnets(evpn_id):
    arp_filter_subnets = ovs.evpns[evpn_id]['properties']['dhcp_pool_range']
    cmd = ("ovs-ofctl add-flow alubr0 \"flow_type=proxy_arp_filter_list,"\
           "evpn_id=%s,proxy_arp_filter_list=%s\""
           % (str(evpn_id), arp_filter_subnets))
    exe(cmd)
    output = helper.getcmdoutput(("ovs-appctl evpn/proxy-arp-filter-list alubr0 %s"
                        % str(evpn_id)))
    result = output.split()
    print result
    if arp_filter_subnets not in result:
       assert 0, ("Expected %s not found in ARP-Filter List" % arp_filter_subnets)
    else:
       logging.debug("%s present in the ARP-Filter List of Evpn: %s"
                     % (arp_filter_subnets, str(evpn_id)))

def test_learn_ip(evpn_id=101):
    arp_filter_subnets = ovs.evpns[evpn_id]['properties']['dhcp_pool_range']
    start_ip, ip = arp_filter_subnets.split('-')
    logging.debug("learning ip %s from ARP-Filter List of Evpn: %s ..."
                  % (ip, str(evpn_id)))
    send_grat_arp_p = multiprocessing.Process(target=NetworkUtil.send_grat_arp,\
                                              args=('br1', ip))
    send_grat_arp_p.start()
    time.sleep(4)
    send_grat_arp_p.terminate()
