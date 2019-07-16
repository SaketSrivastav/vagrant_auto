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
BIDIR_EXIT_DOMAIN = 'vrf_id=%s,ip,.*nw_dst=%s/24,'\
                    'actions=load:%s->NXM_NX_REG2\[\],resubmit\(,26\)'
BIDIR_SNAT = 'vrf_id=%s,ip,reg2=%s,nw_src=%s/24,actions=load:0->NXM_NX_PKT_MARK\[8..29\],note:be.c0.01.de.ad.be.ef.02'
OVERLAY_EXIT_DOMAIN = 'vrf_id=%s,ip,.*nw_dst=%s/24,actions=resubmit\(,26\)'
ovs_pid = 0
def update_bidir_flows(cmd, apply_bidir_nat, apply_bidir_spat,
                       apply_oat, apply_exit_domain):
    op = 'add-flow' if cmd == 'add' else "del-flows"
    links = ovs.tests['bidi-nat'][scenario]['links']
    for link in links:
        c = link['c_domain']
        p = link['p_domain']
        c_spat_ip_from_p = link["c_spat_ip_from_p"]
        p_spat_cfg = link["p_spat_cfg"]
        p_maps = link["p_maps"]
        c_maps = link["c_maps"]
        c_exit_domain = link["c_exit_domain"]

        # Exit_domains
        if apply_exit_domain:
            for v in c_exit_domain:
                exe('ovs-ofctl '+op+' alubr0 "flow_type=route,flags=exit_domain,ip,exit_domain_type=overlay,'\
                    'vrf_id='+str(c)+',nw_dst='+ovs.vms[v+'-veth1']['ip']+'/24"')
            """
            for v in c_exit_domain:
                rule_pattern = (OVERLAY_EXIT_DOMAIN \
                    %(str(hex(int(c))),
                    ipaddr.IPv4Network(ovs.vms[v+'-veth1']['ip']+ '/24').network))
                rule_pattern = (BIDIR_SNAT
                         %(str(hex(int(c))), str(hex(int(p))),
                         ipaddr.IPv4Network(ovs.vms[v+'-veth1']['ip']+ '/24').network))
            """
            logging.info("%s @ Exit-domain %s ..." % (link['name'], op))

        # 1->1 SNAT DNAT maps
        if apply_bidir_nat:
            for m in p_maps:
                exe('ovs-ofctl '+op+' alubr0 "flow_type=route,ip,flags=nat,'\
                    'flags=bidir,vrf_id='+str(p)+',nw_dst='+ovs.vms[m[0]+\
                    '-veth1']['ip']+',public_ip='+m[1]+',pub_vrfid='+str(c)+'"')
            for m in c_maps:
                exe('ovs-ofctl '+op+' alubr0 "flow_type=route,ip,flags=nat,'\
                     'flags=bidir,vrf_id='+str(c)+',nw_dst='+ovs.vms[m[0]+\
                     '-veth1']['ip']+',public_ip='+m[1]+',pub_vrfid='+str(p)+'"')
            logging.info("%s @ Bidir SNAT/DNAT %s ..." % (link['name'], op))
        # spat from  provider to customer list to ->1
        if apply_bidir_spat:
            for spat_ip in p_spat_cfg:
                if op == 'del-flows':
                   exe('ovs-ofctl '+op+' alubr0 "flow_type=route,ip,'\
                       'flags=ecmp,vrf_id='+str(c)+\
                       ',nw_dst='+spat_ip+',n_hop=0|0|0"')
                else:
                   exe('ovs-ofctl '+op+' alubr0 "flow_type=route,ip,flags=bidir,'\
                       'flags=spat,flags=ecmp,vrf_id='+str(c)+\
                       ',nw_dst='+spat_ip+',n_hop=0|1|0,nhop_flag=remote,'\
                       'rnhop_flag=nhop_vrf_id,tep_addr='+str(p)+'"')
                src_ips = ''
                for v in p_spat_cfg[spat_ip]:
                    src_ips = src_ips + ',src_ip=' +ovs.vms[v+'-veth1']['ip']+',src_end_ip='+ovs.vms[v+'-veth1']['ip']
            if op != 'del-flows':
                exe('ovs-ofctl add-flow alubr0 flow_type=spat_cfg,n_maps='+\
                     str(len(p_spat_cfg[spat_ip]))+',src_pfx_vrf='+str(p)+\
                     ',vrf_id='+str(c)+',spat_ip='+spat_ip+','+src_ips)
            logging.info("%s @ Bidir SPAT %s ..." % (link['name'], op))
        if apply_oat:
            # OAT from cutsomer to provider
            exe('ovs-ofctl '+op+' alubr0 "flow_type=route,ip,flags=spat,vrf_id='\
                +str(p)+',nw_dst='+c_spat_ip_from_p+',n_hop=0|1,nhop_flag=remote,'\
                'rnhop_flag=nhop_vrf_id,tep_addr='+str(c)+'"')
            logging.info("%s @ OAT %s ..." % (link['name'], op))

def pytest_generate_tests(metafunc):
    """
    for i in range (metafunc.config.option.count):
        metafunc.parametrize()
    """
    if 'skip_gen' in metafunc.function.__name__:
       return
    idlist = []
    argvalues = []
    global scenario
    scenario = ('all' if metafunc.config.option.all else 'basic')

    if metafunc.function.__name__ == 'test_event_bidir_exit_domain_downgrade' :
       for i in ['delete_provider', 'delete_bidir_nat_spat']:
           idlist.append('Link '+scenario +', Event: '+i)
           argvalues.append(([i]))
    if metafunc.function.__name__ == 'test_delele_bidir_exit_domain':
       for i in ['delete_customer', 'delete_exit_domain']:
           idlist.append('Link '+scenario +', Event: '+i)
           argvalues.append(([i]))
    for link in ovs.tests['bidi-nat'][scenario]['links']:
        link_name = link['name']
        c = link['c_domain']
        p = link['p_domain']
        c_spat_ip_from_p = link["c_spat_ip_from_p"]
        p_spat_cfg = link["p_spat_cfg"]
        c_maps = {}
        p_maps = {}
        for m in link["p_maps"]:
            p_maps[m[0]] = m[1]
        for m in link["c_maps"]:
            c_maps[m[0]] = m[1]
        c_exit_domain = link["c_exit_domain"]
        if 'test_Customer_to_Provider_snat_dnat' == metafunc.function.__name__:
           for c_m in c_maps:
               for p_m in p_maps:
                   idlist.append(scenario +'-'+link_name+', '+c_m+': '\
                                 +ovs.vms[c_m+'-veth1']['ip']\
                                 +'=>'+p_maps[p_m])
                   argvalues.append(([str(c_m), str(p_maps[p_m])]))
        elif 'test_Provider_to_Customer_snat_dnat' == metafunc.function.__name__:
           for p_m in p_maps:
               for c_m in c_maps:
                   idlist.append(scenario+'-'+link_name+', '+p_m+': '\
                                 +ovs.vms[p_m+'-veth1']['ip']\
                                 +'=>'+c_maps[c_m])
                   argvalues.append(([str(p_m), str(c_maps[c_m])]))
        elif 'test_Customer_to_Provider_oat_exit_domain' == metafunc.function.__name__:
           for vm in c_exit_domain:
               for c_m in c_maps:
                   idlist.append(scenario +'-'+link_name+', '+c_m+': '\
                                 +ovs.vms[c_m+'-veth1']['ip']\
                                 +'=>'+ovs.vms[vm+'-veth1']['ip'])
                   argvalues.append(([str(c_m), str(ovs.vms[vm+'-veth1']['ip'])]))
        elif 'test_Provider_to_Customer_spat_dnat' == metafunc.function.__name__:
           for spat in p_spat_cfg:
               s = p_spat_cfg[spat]
               for spat in s:
                   logging.debug("%s" % spat)
                   for c_m in c_maps:
                       idlist.append(scenario +'-'+link_name+', '+spat+': '\
                               +ovs.vms[spat+'-veth1']['ip']+'=>'+c_maps[c_m])
                       argvalues.append(([str(spat), str(c_maps[c_m])]))
    metafunc.parametrize(metafunc.fixturenames, argvalues, ids=idlist)

def setup_module():
    logging.info("\n")
    exe('ip netns exec spat_ns sysctl net.ipv4.ip_forward=1')
    exe('ip netns exec spat_ns iptables -t nat -F')
    exe('ip netns exec spat_ns iptables -t mangle -F')
    global ovs_pid
    ovs_pid = helper.get_pid("ovs-vswitchd")
    logging.info("ovs-vswitchd pid : %d" % ovs_pid)

    ovs.ovs_bump_gen_id()
    ovs.ovs_cleanup()
    ovs.vm_port_setup()
    global flows_b4_setup
    flows_b4_setup = ovs.ovs_flows()
    logging.info("Number of flows at module setup: %d" % len(flows_b4_setup))

    update_bidir_flows('add', True, True, True, True)

def teardown_module():
    print("")
    #update_bidir_flows('del-flows',\
    #        ovs.tests['bidi-nat'][scenario]['links'])
def setup_function():
    print("")
    cmd = 'ip netns exec spat_ns iptables -t nat -Z;\
           ip netns exec spat_ns iptables -t mangle -Z;'
    exe(cmd)
    cmd = 'ovs-appctl bridge/clear-flow-stats alubr0'
    exe(cmd)

def test_Provider_to_Customer_snat_dnat(provider_src,\
                                        customer_dst_alias):
    NetworkUtil.send_icmp(provider_src, ovs.vms[provider_src+'-veth1']['mac'],\
            ovs.evpns[ovs.vms[provider_src+'-veth1']['evpn']]['properties']['gw_mac'],\
            ovs.vms[provider_src+'-veth1']['ip'],\
            customer_dst_alias)
    rules = ovs.ovs_hit_rules()
    logging.debug("%s" % rules)

def test_Customer_to_Provider_snat_dnat(customer_src,\
                                        provider_dst_alias):
    NetworkUtil.send_icmp(customer_src, ovs.vms[customer_src+'-veth1']['mac'],\
            ovs.evpns[ovs.vms[customer_src+'-veth1']['evpn']]['properties']['gw_mac'],\
            ovs.vms[customer_src+'-veth1']['ip'],\
            provider_dst_alias)
    rules = ovs.ovs_hit_rules()
    logging.debug("%s" % rules)

def test_Provider_to_Customer_spat_dnat(provider_src,\
                                        customer_dst_alias):
    NetworkUtil.send_icmp(provider_src, ovs.vms[provider_src+'-veth1']['mac'],\
            ovs.evpns[ovs.vms[provider_src+'-veth1']['evpn']]['properties']['gw_mac'],\
            ovs.vms[provider_src+'-veth1']['ip'],\
            customer_dst_alias)
    rules = ovs.ovs_hit_rules()
    logging.debug("%s" % rules)

def test_Customer_to_Provider_oat_exit_domain(customer_src,\
                                              provider_priv_dst):
    NetworkUtil.send_icmp(customer_src, ovs.vms[customer_src+'-veth1']['mac'],\
            ovs.evpns[ovs.vms[customer_src+'-veth1']['evpn']]['properties']['gw_mac'],\
            ovs.vms[customer_src+'-veth1']['ip'],\
                provider_priv_dst)
    rules = ovs.ovs_hit_rules()
    logging.debug("%s" % rules)

def do_event(event):
    links = ovs.tests['bidi-nat'][scenario]['links']
    logging.info("\n!!! EVENT : %s !!!\n" % event)
    if event == 'delete_provider':
        for link in links:
            c = link['c_domain']
            p = link['p_domain']
            exe("ovs-ofctl del-vrf alubr0 "+str(p))
            logging.info("Deleting provider vrf %s" % str(p))
    elif event == 'delete_customer':
        for link in links:
            c = link['c_domain']
            exe("ovs-ofctl del-vrf alubr0 "+str(c))
            logging.info("Deleting customer vrf %s" % str(c))
    elif (event == "delete_bidir_nat_spat"):
        update_bidir_flows('delete', True, True, False, False)
    elif (event == "add_bidir_nat_spat"):
        update_bidir_flows('add', True, True, False, False)
    elif (event == "delete_bidir_nat"):
        update_bidir_flows('delete', True, False, False, False)
    elif (event == "add_bidir_nat"):
        update_bidir_flows('add', True, False, False, False)
    elif (event == "delete_bidir_spat"):
        update_bidir_flows('delete', False, True, False, False)
    elif (event == "add_bidir_spat"):
        update_bidir_flows('add', False, True, False, False)
    elif (event == "add_exit_domain"):
        update_bidir_flows('add', False, False, False, True)
    elif (event == "delete_exit_domain"):
        update_bidir_flows('delete', False, False, False, True)
    elif (event == "add_bidir_nat"):
        update_bidir_flows('add', True, False, False, False)
    else:
        assert 0, ("Event %s not found" % event)

def do_expect(expect_rule_type):
    links = ovs.tests['bidi-nat'][scenario]['links']

    logging.info("\n<<< EXPECT : %s >>>\n" % expect_rule_type)
    for link in links:
        c = link['c_domain']
        p = link['p_domain']
        c_spat_ip_from_p = link["c_spat_ip_from_p"]
        p_spat_cfg = link["p_spat_cfg"]
        p_maps = link["p_maps"]
        c_maps = link["c_maps"]

        c_exit_domain = link["c_exit_domain"]
        e = ""
        bidir = True if (expect_rule_type == 'bidir_exit_domain') else False
        if expect_rule_type in ['bidir_exit_domain', 'overlay_exit_domain' ] :
           for v in c_exit_domain:
                rule_pattern = (BIDIR_EXIT_DOMAIN
                       %(str(hex(int(c))),
                         ipaddr.IPv4Network(ovs.vms[v+'-veth1']['ip']+ '/24').network,
                         str(hex(int(p)))))
                rule = ovs.expect_rule(rule_pattern, bidir, 'Bidir Exit-Domain')

                rule_pattern = (BIDIR_SNAT
                         %(str(hex(int(p))), str(hex(int(c))),
                         ipaddr.IPv4Network(ovs.vms[v+'-veth1']['ip']+ '/24').network))
                ovs.expect_rule(rule_pattern, bidir, 'table=26 SNAT')
                rule_pattern = (BIDIR_SNAT
                         %(str(hex(int(c))), str(hex(int(p))),
                         ipaddr.IPv4Network(ovs.vms[v+'-veth1']['ip']+ '/24').network))
                ovs.expect_rule(rule_pattern, False, 'table=26 SNAT')
                rule_pattern = (OVERLAY_EXIT_DOMAIN \
                    %(str(hex(int(c))),
                    ipaddr.IPv4Network(ovs.vms[v+'-veth1']['ip']+ '/24').network))
                ovs.expect_rule(rule_pattern,
                                not bidir, 'Overlay Exit-Domain')

def test_event_bidir_create_link_create_exit_domain_delete_link_skip_gen():
    do_event('add_bidir_spat')
    do_event('add_exit_domain')
    do_event('add_bidir_nat')

    do_expect('bidir_exit_domain')

    do_event('delete_bidir_spat')
    do_event('delete_bidir_nat')

    do_expect('overlay_exit_domain')

    ovs.vm_port_setup()
    update_bidir_flows('add', True, True, True, True)

def test_event_bidir_exit_domain_downgrade(event):
    links = ovs.tests['bidi-nat'][scenario]['links']
    for link in links:
        c = link['c_domain']
        p = link['p_domain']
        c_spat_ip_from_p = link["c_spat_ip_from_p"]
        p_spat_cfg = link["p_spat_cfg"]
        p_maps = link["p_maps"]
        c_maps = link["c_maps"]

        c_exit_domain = link["c_exit_domain"]
        e = ""
        for v in c_exit_domain:
            rule_pattern = (BIDIR_EXIT_DOMAIN
                   %(str(hex(int(c))),
                     ipaddr.IPv4Network(ovs.vms[v+'-veth1']['ip']+ '/24').network,
                     str(hex(int(p)))))
            rule = ovs.expect_rule(rule_pattern, True, 'Bidir Exit-Domain')

            rule_pattern = (BIDIR_SNAT
                     %(str(hex(int(p))), str(hex(int(c))),
                     ipaddr.IPv4Network(ovs.vms[v+'-veth1']['ip']+ '/24').network))
            ovs.expect_rule(rule_pattern, True, 'table=26 SNAT')
            rule_pattern = (BIDIR_SNAT
                     %(str(hex(int(c))), str(hex(int(p))),
                     ipaddr.IPv4Network(ovs.vms[v+'-veth1']['ip']+ '/24').network))
            ovs.expect_rule(rule_pattern, False, 'table=26 SNAT')

    # Delete provider
    # Delete bidir spat,nat
    do_event(event)
    for link in links:
        c = link['c_domain']
        p = link['p_domain']
        c_spat_ip_from_p = link["c_spat_ip_from_p"]
        p_spat_cfg = link["p_spat_cfg"]
        p_maps = link["p_maps"]
        c_maps = link["c_maps"]

        c_exit_domain = link["c_exit_domain"]

        for v in c_exit_domain:
            rule_pattern = (BIDIR_EXIT_DOMAIN
                   %(str(hex(int(c))),
                     ipaddr.IPv4Network(ovs.vms[v+'-veth1']['ip']+ '/24').network,
                     str(hex(int(p)))))
            ovs.expect_rule(rule_pattern, False, 'Bidir Exit-Domain')
            rule_pattern = (BIDIR_SNAT
                     %(str(hex(int(p))), str(hex(int(c))),
                     ipaddr.IPv4Network(ovs.vms[v+'-veth1']['ip']+ '/24').network))
            ovs.expect_rule(rule_pattern, False, 'table=26 SNAT')
            rule_pattern = (BIDIR_SNAT
                     %(str(hex(int(c))), str(hex(int(p))),
                     ipaddr.IPv4Network(ovs.vms[v+'-veth1']['ip']+ '/24').network))
            ovs.expect_rule(rule_pattern, False, 'table=26 SNAT')

            rule_pattern = (OVERLAY_EXIT_DOMAIN
                %(str(hex(int(c))),
                  ipaddr.IPv4Network(ovs.vms[v+'-veth1']['ip']+ '/24').network))
            ovs.expect_rule(rule_pattern, True, 'Overlay Exit-domain')
    ovs.vm_port_setup()
    update_bidir_flows('add', True, True, True, True)

def test_delele_bidir_exit_domain(event):
    links = ovs.tests['bidi-nat'][scenario]['links']
    for link in links:
        c = link['c_domain']
        p = link['p_domain']
        c_spat_ip_from_p = link["c_spat_ip_from_p"]
        p_spat_cfg = link["p_spat_cfg"]
        p_maps = link["p_maps"]
        c_maps = link["c_maps"]

        c_exit_domain = link["c_exit_domain"]
        e = ""
        for v in c_exit_domain:
            rule_pattern = (BIDIR_EXIT_DOMAIN
                   %(str(hex(int(c))),
                     ipaddr.IPv4Network(ovs.vms[v+'-veth1']['ip']+ '/24').network,
                     str(hex(int(p)))))
            ovs.expect_rule(rule_pattern, True, 'Bidir Exit-domain')

            rule_pattern = (BIDIR_SNAT
                     %(str(hex(int(p))), str(hex(int(c))),
                     ipaddr.IPv4Network(ovs.vms[v+'-veth1']['ip']+ '/24').network))
            ovs.expect_rule(rule_pattern, True, 'table=26 SNAT')
            rule_pattern = (BIDIR_SNAT
                     %(str(hex(int(c))), str(hex(int(p))),
                     ipaddr.IPv4Network(ovs.vms[v+'-veth1']['ip']+ '/24').network))
            ovs.expect_rule(rule_pattern, False, 'table=26 SNAT')

    #del customer
    #del exit-domain
    do_event(event)
    for link in links:
        c = link['c_domain']
        p = link['p_domain']
        c_spat_ip_from_p = link["c_spat_ip_from_p"]
        p_spat_cfg = link["p_spat_cfg"]
        p_maps = link["p_maps"]
        c_maps = link["c_maps"]

        c_exit_domain = link["c_exit_domain"]

        for v in c_exit_domain:
            rule_pattern = (BIDIR_EXIT_DOMAIN
                   %(str(hex(int(c))),
                     ipaddr.IPv4Network(ovs.vms[v+'-veth1']['ip']+ '/24').network,
                     str(hex(int(p)))))
            ovs.expect_rule(rule_pattern, False, 'Bidir Exit-Domain')

            rule_pattern = (BIDIR_SNAT
                     %(str(hex(int(p))), str(hex(int(c))),
                     ipaddr.IPv4Network(ovs.vms[v+'-veth1']['ip']+ '/24').network))
            ovs.expect_rule(rule_pattern, False, 'table=26 SNAT')
            rule_pattern = (BIDIR_SNAT
                     %(str(hex(int(c))), str(hex(int(p))),
                     ipaddr.IPv4Network(ovs.vms[v+'-veth1']['ip']+ '/24').network))
            ovs.expect_rule(rule_pattern, False, 'table=26 SNAT')

            rule_pattern = (OVERLAY_EXIT_DOMAIN
                %(str(hex(int(c))),
                  ipaddr.IPv4Network(ovs.vms[v+'-veth1']['ip']+ '/24').network))
            ovs.expect_rule(rule_pattern, False, 'Overlay Exit-Domain')
    ovs.vm_port_setup()
    update_bidir_flows('add', True, True, True, True)

@pytest.mark.run(after='test_Controller_event_bump_gen_id_cleanup')
def test_exit_domain_upgrade_to_bidir_skip_gen():
    ovs.ovs_bump_gen_id()
    ovs.ovs_cleanup()

    ovs.vm_port_setup()
    links = ovs.tests['bidi-nat'][scenario]['links']
    #Apply Exit-domain
    update_bidir_flows('add', False, False, False, True)
    #Apply bidir-nat
    update_bidir_flows('add', True, False, False, False)
    for link in links:
        c = link['c_domain']
        p = link['p_domain']
        c_spat_ip_from_p = link["c_spat_ip_from_p"]
        p_spat_cfg = link["p_spat_cfg"]
        p_maps = link["p_maps"]
        c_maps = link["c_maps"]

        c_exit_domain = link["c_exit_domain"]
        for v in c_exit_domain:
            rule_pattern = (BIDIR_EXIT_DOMAIN
                   %(str(hex(int(c))),
                     ipaddr.IPv4Network(ovs.vms[v+'-veth1']['ip']+ '/24').network,
                     str(hex(int(p)))))
            ovs.expect_rule(rule_pattern, True, 'Bidir Exit-Domain')

            rule_pattern = (BIDIR_SNAT
                     %(str(hex(int(p))), str(hex(int(c))),
                     ipaddr.IPv4Network(ovs.vms[v+'-veth1']['ip']+ '/24').network))
            ovs.expect_rule(rule_pattern, True, 'table=26 SNAT')
            rule_pattern = (BIDIR_SNAT
                     %(str(hex(int(c))), str(hex(int(p))),
                     ipaddr.IPv4Network(ovs.vms[v+'-veth1']['ip']+ '/24').network))
            ovs.expect_rule(rule_pattern, False, 'table=26 SNAT')

    ovs.vm_port_setup()
    update_bidir_flows('add', True, True, True, True)

@pytest.mark.second_to_last
def test_Controller_event_bump_gen_id_cleanup_skip_gen():
    ovs.ovs_bump_gen_id()
    exe("echo \"\" > /var/log/openvswitch/ovs-vswitchd.log")
    ovs.vm_port_setup()
    ovs.ovs_cleanup()
    flows_after_cleanup = ovs.ovs_flows()

    if len(flows_b4_setup) > len(flows_after_cleanup):
       logging.critical("Missing flows After Cleanup => ")
       for i in flows_b4_setup.difference(flows_after_cleanup):
           logging.critical(colorred.format(i))
    elif len(flows_b4_setup) < len(flows_after_cleanup):
       logging.critical("\nFlows escaped cleanup => ")
       for i in flows_after_cleanup.difference(flows_b4_setup):
           logging.critical(colorred.format(i))
    else:
        logging.critical(colorgrn.format("Expected flows %d, found %d after Cleanup"\
            % (len(flows_b4_setup), len(flows_after_cleanup))))

    assert len(flows_b4_setup) == len(flows_after_cleanup), \
           ("Expected flows %d, found %d after Cleanup"\
            % (len(flows_b4_setup), len(flows_after_cleanup)))
@pytest.mark.xfail
def test_ovs_crash_on_customer_delete_skip_gen():
    update_bidir_flows('add', True, True, True, True)
    do_event("delete_customer")
    ovs.ovs_check_crash()
    ovs.vm_port_setup()
    update_bidir_flows('add', True, True, True, True)

@pytest.mark.last
def test_Controller_event_bump_gen_id_replay_flows_and_cleanup_skip_gen():

    update_bidir_flows('add', True, True, True, True)
    flows_b4_cleanup = ovs.ovs_flows()

    ovs.ovs_bump_gen_id()

    ovs.vm_port_setup()
    update_bidir_flows('add', True, True, True, True)

    #exe("ovs-ofctl add-flow alubr0 \"flow_type=ofctl-events,flags=cleanup\"")
    ovs.ovs_cleanup()

    flows_after_cleanup = ovs.ovs_flows()

    if len(flows_b4_cleanup) > len(flows_after_cleanup):
       logging.critical("\nMissing flows After Cleanup => ")
       for i in flows_b4_cleanup.difference(flows_after_cleanup):
           logging.critical(colorred.format(i))
    elif len(flows_b4_cleanup) < len(flows_after_cleanup):
       logging.critical("\nExtra flows After Cleanup => ")
       for i in flows_after_cleanup.difference(flows_b4_cleanup):
           logging.critical(colorred.format(i))
    else:
        logging.info(colorgrn.format("Expected flows %d, found %d after Cleanup"\
            % (len(flows_b4_cleanup), len(flows_after_cleanup))))

    assert len(flows_b4_cleanup) == len(flows_after_cleanup), \
           ("Expected flows %d, found %d after Cleanup"\
            % (len(flows_b4_cleanup), len(flows_after_cleanup)))
