#! /usr/bin/python
import subprocess
def parse_ovs_dhcp_decline_show(evpn_id):
    dhcp_pool_info = {}
    print("parse_ovs_dhcp_decline_show evpn_id: %s" % str(evpn_id))
    p = subprocess.Popen(["ovs-appctl", "evpn/dhcp-pool-show", "alubr0", str(evpn_id)],
                     stdout=subprocess.PIPE)
    output = p.communicate()[0]
    print output
    flag = False
    for s in output.split("\n"):
        if not len(s):
            continue
        if s == "Declined IP addresses":
           flag = True;
           continue
        if flag:
           dhcp_entry_obj = dhcp_entry_class("00:00:00:00:00:00", s.split()[0])
           if dhcp_pool_info.has_key(evpn_id) :
              dhcp_pool_info[evpn_id].append (dhcp_entry_obj)
           else :
              dhcp_pool_info[evpn_id] = []
              dhcp_pool_info[evpn_id].append (dhcp_entry_obj)
           print s.split()[0]
    return dhcp_pool_info
def parse(cmd):
    output = subprocess.check_output(cmd, shell=True)
    print output
    result = {}
    for row in output.split('\n'):
        if (row == '\n'):
            continue;
        print(row)
        #if ': ' in row:
        #    key, value = row.split(': ')
        #    result[key.strip(' .')] = value.strip()
    print(result)
parse("ovs-appctl evpn/dhcp-pool-show alubr0 22")
#parse_ovs_dhcp_decline_show("22")
