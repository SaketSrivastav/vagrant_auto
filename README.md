# VRS Automation

Testing Nuage VRS code generally involves running Sanity on a testbed & spawning multiple vports/bridge ports.
And on top of that we configure necessary flows & we verify if the feature/bug fix is working based on traffic verification/some config on ovs.

The objective of this project is to be able to perform unit-testing & debugging without depending on the testbed infra.

## Getting Started

To check out the code do:

git clone git@github.mv.usa.alcatel.com:vdeore/automation.git

cd automation

## Prerequisites
1. VirtualBox
2. Vagrant

In order to create test VMs as per definition in repo, you will need Vagrant.
If you are running this setup on new vm, not created by above Vagrant, then you will need all the dependencies satisfied.
the required rpms are mentioned in bootstrap.sh file.

If you wish to run traffic it will be good idea to have scapy installed.

### Bringing up Test VMs:


```
vdeore@vdeore:/var/nfs/ws/automation$ cd Vagrant/multivm/Centos-7.1
vdeore@vdeore:/var/nfs/ws/automation/Vagrant/multivm/Centos-7.1$ vagrant status
Current machine states:

dev_el7_48_1              not running (virtualbox)
ovs_el7_48_1              not running (virtualbox)
dev_el7_44_1              not running (virtualbox)
ovs_el7_44_1              not running (virtualbox)

This environment represents multiple VMs. The VMs are all listed

vdeore@vdeore:/var/nfs/ws/automation/Vagrant/multivm/Centos-7.1$ vagrant  up  ovs_el7_44_1
/usr/lib/ruby/vendor_ruby/vagrant/util/which.rb:32: warning: Insecure world writable dir /usr/global in PATH, mode 040777
Bringing machine 'ovs_el7_44_1' up with 'virtualbox' provider...
[ovs_el7_44_1] Importing base box 'bento/centos-7.1'...
[ovs_el7_44_1] Matching MAC address for NAT networking...
[ovs_el7_44_1] Setting the name of the VM...
[ovs_el7_44_1] Clearing any previously set forwarded ports...
[ovs_el7_44_1] Clearing any previously set network interfaces...
[ovs_el7_44_1] Available bridged network interfaces:
1) eth0
2) vmnet8
3) virbr0
4) vmnet1
5) docker0
What interface should the network bridge to? 1
[ovs_el7_44_1] Preparing network interfaces based on configuration...
[ovs_el7_44_1] Forwarding ports...
[ovs_el7_44_1] -- 22 => 2222 (adapter 1)
[ovs_el7_44_1] Running 'pre-boot' VM customizations...
[ovs_el7_44_1] Booting VM...
[ovs_el7_44_1] Waiting for machine to boot. This may take a few minutes...
[ovs_el7_44_1] Machine booted and ready!

```
This will bring up a el7 vm with kernel 3.10.0-229.44.1.el7.x86_64(same as our dc testbeds.).
Similarly you can bring up ovs_el7_48_1 will bring up VM with kernel 3.10.0-229.44.1.el7.x86_64(same as nsg.)
You will need to reboot these VMs once to boot into new kernel.

Note: One optimization would be to package these VMs as Vabgrant Boxes.

## OVS Setup
Once you have VMs ready, you can login to the VMs & install ovs rpms from /usr/global/images.
After that you can follow below steps to resolve the vports.

```
vdeore@vdeore:/var/nfs/ws/automation/Vagrant/multivm/Centos-7.1$ cd ../../../config
root@VagrantCentos7:~/nfs/ws/automation/config (master)# ./setup.py -h
usage: setup.py [-h] [--cfg-file CFG_FILE] [--vms VMS] [--brs BRS] [--dynamic]
                [-v]

optional arguments:
  -h, --help            show this help message and exit
  --cfg-file CFG_FILE   JSON config-file
  --vms VMS             Number of vm-vports
  --brs BRS             Number of bridge-vports
  --dynamic, --dynamic  Generate vms, ips dynamically
  -v, --verbose         Increase output verbosity

```
#Note: config.json is the default file it reads teh config from. That has total of 16 vms.
```
root@VagrantCentos7:~/nfs/ws/automation/config (master)# ./setup.py -v

port-cfg Generated ...
Config-File : config.json
        0.   ovs-restart                      [ Restart the OVS ]
        1.   VRS setup                        [ setup routes for vm resolution ]
        2.   NSG setup                        [ setup routes for bridge port resolution ]
        3.   remote static routes             [ configure static routes ]
        4.   fip config                       [ configure fip routes ]
        5.   vrf/show
        6.   evpn/show
        7.   vm/port-show
        8.   bridge/port-show
        9.   Egress fip qos config show
        10.  Topology                         [ current topoloy, may need to re-init in  case of auto-generate ]
        11.  VM DHCP                          [ dhclient for vports, assign ipv6 if configured ]
        12.  re intialize                     [ destroy and recreate namespaces, xmls, veth pairs ]
        13.  Cleanup                          [ destroy namespaces, xmls, veth pairs ]
        14.  Nsg uplink setup                 [ NSG uplink resolution ]
Choose ?
```
On a new Test VM in order to setup VMs & namespaces you will need to do option 13, option 12 in that order.

1. Option 13(Cleanup):
    1. It deletes the previously created namespaces & vethpairs.

2. Option 12(Re Intialize):
    1. It creates the veth-pairs, namespaces xml definitions.
       this is an equivalent of virsh define.
Once the two steps are done you can restart ovs (option: 1) & do VRs setup(option 1).
3. Option 1(VRS Setup):
    1. It adds one end of veth-pair to alubr0 bridge.
    2. It creates VRS & evpn as per the topology specified in config.json
    3. It executes the ofctl for vm port resolution as below
        1. evpn membership
        2. bacis acls
        3. EVPN routes
        4. qos config
        5. dhcp flow
        6. evpn-redirect
        7. arp-route

Now we have all the flows, but the veth-pair still dont have any ips assigned, for that we need to do
Option 11(VM DHCP):
    This just starts dhclient from withing each of the namespaces.

After these steps all the vms will be resolved, the setup is ready to be used.

#Note: Onwards you dont need to cleanup & re-initiliaze, you only need to install new rpms & do VRS Setup(option-1).


#### Sending Traffic

Once you have the setup, you can start sending traffic from within namespaces.

```
root@VagrantCentos7:~/nfs/ws/automation/unit-tests (master)# ip netns exe vm1 ping 2.2.2.2 -c 10
PING 2.2.2.2 (2.2.2.2) 56(84) bytes of data.
64 bytes from 2.2.2.2: icmp_seq=1 ttl=63 time=3.09 ms
64 bytes from 2.2.2.2: icmp_seq=2 ttl=63 time=0.094 ms
64 bytes from 2.2.2.2: icmp_seq=3 ttl=63 time=0.091 ms

```

####  NSG Network Uplink resolution (option 14):
Now, we can add network uplink as per information provided in config.json file(from ["nsg"] tag parameters).
It works as follows

1. creates a symlink for /home/root to git repo dir that has mergedconfig.json & nsg-stat.json (with port1 replaced with eth0, & port2 replaced with eth1)
2. now based on information in config.json derived the ip & gw-ip etc. & set them as appropriate environmental variables& called update_underlay function imported from nuage-dhcp-hook.
so this is as if that port has come up & generated dhcp-up event.

After this the network uplink gets added to test-vm & show up in network/port-show.

##### What is not working ? :
1. network/port-show shows the added uplinks, but uplink-priority-map still shows as 0x0, this is because as per VRS code network uplink is considered DOWN if there is no controller connected to it. This is done in function vrs_uplink_update_priority_bitmap.

##### Temp Workaround:
To overcome this we might need some handling in the code. But to make it work in test vm , we can compile an image locally that always returns vrs_uplink_controller_is_connected true.

##### Possible Optimization for NSG Network uplink resolution:
There is still room for improvement, listing down here
1. we can generate mergedconfig.json & nsg-state.json based on the requirement of the testcase.

##### Sample Output Network uplink resolution:
```
root@VagrantCentos7:~/nfs/ws/nsg_jsons# ovs-appctl network/port-show  
uplink-priority-map: 0x0
name: eth0
        state: up       priority: primary1      alias: 
        gen-id: 74      stats-disabled: 1       stats-interval: 0
        ip: 100.100.100.1       uuid:00000000-0000-0000-0000-000000000000
        uplink-type: Network
        underlay-id: 0 uplink-id: 0 advertise_cr: OPENFLOW
        Capabilities: NAT|ROUTE_UNDERLAY|
        Egress QoS Stats - Export count (to controller): 0
        Egress Qos Stats - Export count (to stats-collector): 0
        Interface Stats - Export count (to stats-collector): 0
        Cumulative Interface Stats-pushed-to-stats-collector:
                tx_bytes:0              tx_pkt_count:0
                tx_errors:0             tx_dropped:0
                rx_bytes:0              rx_pkt_count:0
                rx_errors:0             rx_dropped:0
        Current Interface Stats-pushed-to-stats-collector:
                tx_bytes:0              tx_pkt_count:0
                tx_errors:0             tx_dropped:0
                rx_bytes:0              rx_pkt_count:0
                rx_errors:0             rx_dropped:0
name: eth1
        state: up       priority: secondary2    alias: 
        gen-id: 74      stats-disabled: 1       stats-interval: 0
        ip: 135.227.177.206     uuid:00000000-0000-0000-0000-000000000000
        uplink-type: Network
        underlay-id: 0 uplink-id: 0 advertise_cr: OPENFLOW
        Capabilities: NAT|ROUTE_UNDERLAY|
        Egress QoS Stats - Export count (to controller): 0
        Egress Qos Stats - Export count (to stats-collector): 0
        Interface Stats - Export count (to stats-collector): 0
        Cumulative Interface Stats-pushed-to-stats-collector:
                tx_bytes:0              tx_pkt_count:0
                tx_errors:0             tx_dropped:0
                rx_bytes:0              rx_pkt_count:0
                rx_errors:0             rx_dropped:0
        Current Interface Stats-pushed-to-stats-collector:
                tx_bytes:0              tx_pkt_count:0
                tx_errors:0             tx_dropped:0
                rx_bytes:0              rx_pkt_count:0
                rx_errors:0             rx_dropped:0
```

### Running unit tests

One you have test VM setup, you can run pytest on this setup.
Below is an example of pytest for bgp feature i have been working on.

Before executing the tests you can collect testcases, this shows up all the test-cases as per the params.
You can parameterize tests.
```
root@VagrantCentos7:~/nfs/ws/automation/unit-tests (master)# py.test --spec  --instafail --tb=line  --collect-only test_bidir.py
===================================================================================== test session starts =====================================================================================
platform linux2 -- Python 2.7.5, pytest-3.5.1, py-1.5.3, pluggy-0.6.0
rootdir: /root/nfs/ws/automation/unit-tests, inifile:
plugins: spec-1.1.0, instafail-0.3.0, ordering-0.5
collected 17 items
<Module 'test_bidir.py'>
  <Function 'test_Provider_to_Customer_snat_dnat[basic-link1(1=>2), vm3: 2.2.2.2=>100.1.1.20]'>
  <Function 'test_Provider_to_Customer_snat_dnat[basic-link1(1=>2), vm3: 2.2.2.2=>100.1.1.10]'>
  <Function 'test_Customer_to_Provider_snat_dnat[basic-link1(1=>2), vm4: 20.1.1.10=>200.1.1.10]'>
  <Function 'test_Customer_to_Provider_snat_dnat[basic-link1(1=>2), vm2: 10.1.1.10=>200.1.1.10]'>
  <Function 'test_Provider_to_Customer_spat_dnat[basic-link1(1=>2), vm1: 1.1.1.1=>100.1.1.20]'>
  <Function 'test_Provider_to_Customer_spat_dnat[basic-link1(1=>2), vm1: 1.1.1.1=>100.1.1.10]'>
  <Function 'test_Customer_to_Provider_oat_exit_domain[basic-link1(1=>2), vm4: 20.1.1.10=>1.1.1.1]'>
  <Function 'test_Customer_to_Provider_oat_exit_domain[basic-link1(1=>2), vm2: 10.1.1.10=>1.1.1.1]'>
  <Function 'test_event_bidir_create_link_create_exit_domain_delete_link_skip_gen'>
  <Function 'test_event_bidir_exit_domain_downgrade[Link basic, Event: delete_provider]'>
  <Function 'test_event_bidir_exit_domain_downgrade[Link basic, Event: delete_bidir_nat_spat]'>
  <Function 'test_delele_bidir_exit_domain[Link basic, Event: delete_customer]'>
  <Function 'test_delele_bidir_exit_domain[Link basic, Event: delete_exit_domain]'>
  <Function 'test_exit_domain_upgrade_to_bidir_skip_gen'>
  <Function 'test_ovs_crash_on_customer_delete_skip_gen'>
  <Function 'test_Controller_event_bump_gen_id_cleanup_skip_gen'>
  <Function 'test_Controller_event_bump_gen_id_replay_flows_and_cleanup_skip_gen'>

================================================================================ no tests ran in 0.39 seconds =================================================================================


root@VagrantCentos7:~/nfs/ws/automation/unit-tests (master)# py.test --spec  --instafail --tb=line test_bgp.py
===================================================================================== test session starts =====================================================================================
platform linux2 -- Python 2.7.5, pytest-3.5.1, py-1.5.3, pluggy-0.6.0
rootdir: /root/nfs/ws/automation/unit-tests, inifile:
plugins: spec-1.1.0, instafail-0.3.0, ordering-0.5
collected 27 items

test_bgp.py::
    [PASS]  Update bgp routes[add-100.100.0.0/16-1-11]
    [PASS]  Update bgp routes[delete-100.100.0.0/16-1-11]
    [PASS]  Evpn flag updates evpn routes[1-11]
    [PASS]  Evpn flag updates evpn routes[1-12]
    [PASS]  Evpn flag updates evpn routes[2-21]
    [PASS]  Evpn flag updates evpn routes[2-22]
    [PASS]  Evpn flag updates bgp routes[100.100.0.0/16-1-11]
    [PASS]  Evpn flag updates bgp routes[101.100.0.0/16-1-12]
    [PASS]  Evpn flag updates bgp routes[102.100.0.0/16-2-21]
    [PASS]  Evpn flag updates bgp routes[103.100.0.0/16-2-22]
    [PASS]  Evpn flag updates bgp routes[104.100.0.0/16-4-41]
    [PASS]  Evpn flag updates bgp routes[105.100.0.0/16-4-42]
    [PASS]  Evpn flag updates local static routes[200.100.0.0/16-vm1-veth1-1-11]
    [PASS]  Evpn flag updates local static routes[201.100.0.0/16-vm3-veth1-1-12]
    [PASS]  Evpn flag updates local static routes[202.100.0.0/16-vm2-veth1-2-21]
    [PASS]  Evpn flag updates local static routes[203.100.0.0/16-vm4-veth1-2-22]
    [PASS]  Evpn flag updates local static routes[204.100.0.0/16-vm5-veth1-4-41]
    [PASS]  Evpn flag updates local static routes[205.100.0.0/16-vm7-veth1-4-42]
    [PASS]  Evpn flag updates local static routes[206.100.0.0/16-vm6-veth1-5-51]
    [PASS]  Evpn flag updates local static routes[207.100.0.0/16-vm8-veth1-5-52]
    [PASS]  Evpn delete[100.100.0.0/16-1-11]
    [PASS]  Evpn delete[102.100.0.0/16-2-21]
    [PASS]  Evpn delete[103.100.0.0/16-2-22]
    [PASS]  Evpn delete[104.100.0.0/16-4-41]
    [PASS]  Evpn delete[105.100.0.0/16-4-42]
    [PASS]  Evpn flag updates evpn routes same cidr[1-11-4-41]
    [PASS]  Evpn flag updates evpn routes same cidr[1-12-4-42]                                                                                                                          [100%]

================================================================================== 27 passed in 6.60 seconds ==================================================================================

py.test can be run in more verbose mode as well, so that it dumps all the logs on console or in a logfile.

```
#### Topology:
Example of one the topologies
```
VRS Topology:
        vrf_id: 1(0x1)
            evpn_id: 11(0xb) GW: 1.1.1.254 GWv6: 2001:0:0:11::254
                        [ vm1-veth1 ]
                         ip:1.1.1.1          2001:0:0:11::11
                                [ FIP ] : 10.10.10.10      0x3
                        [ vm9-veth1 ]
                         ip:1.1.1.2          2001:0:0:11::12
                                [ FIP ] : 10.10.10.11      0x3
            evpn_id: 12(0xc) GW: 2.2.2.254 GWv6: 2001:0:0:12::254
                        [ vm3-veth1 ]
                         ip:2.2.2.2          2001:0:0:12::3
                                [ FIP ] : 3.3.3.2          0x3
                        [ vm11-veth1 ]
                         ip:2.2.2.3          2001:0:0:12::4
                                [ FIP ] : 3.3.3.3          0x3
        vrf_id: 2(0x2)
            evpn_id: 21(0x15) GW: 10.0.0.254 GWv6: 2001:0:0:21::254
                        [ vm10-veth1 ]
                         ip:10.1.1.11        2001:0:0:21::3
                                [ FIP ] : 4.4.4.1          0x3
                        [ vm2-veth1 ]
                         ip:10.1.1.10        2001:0:0:21::2
                                [ FIP ] : 4.4.4.1          0x3
            evpn_id: 22(0x16) GW: 20.0.0.254 GWv6: 2001:0:0:22::254
                        [ vm4-veth1 ]
                         ip:20.1.1.10        2001:0:0:22::4
                                [ FIP ] : 10.10.10.11      0x3
                        [ vm12-veth1 ]
                         ip:20.1.1.11        2001:0:0:22::5
                                [ FIP ] : 10.10.10.12      0x3
        vrf_id: 3(0x3)
        vrf_id: 4(0x4)
            evpn_id: 41(0x29) GW: 1.1.1.254 GWv6: 2001:0:0:41::254
                        [ vm13-veth1 ]
                         ip:1.1.1.3          2001:0:0:41::6
                                [ FIP ] : 10.10.10.13      0x3
                        [ vm5-veth1 ]
                         ip:1.1.1.2          2001:0:0:41::5
                                [ FIP ] : 10.10.10.12      0x3
            evpn_id: 42(0x2a) GW: 2.2.2.254 GWv6: 2001:0:0:42::254
                        [ vm15-veth1 ]
                         ip:2.2.2.4          2001:0:0:42::8
                                [ FIP ] : 10.10.10.15      0x3
                        [ vm7-veth1 ]
                         ip:2.2.2.3          2001:0:0:42::7
                                [ FIP ] : 10.10.10.14      0x3
        vrf_id: 5(0x5)
            evpn_id: 51(0x33) GW: 10.0.0.254 GWv6: 2001:0:0:51::254
                        [ vm6-veth1 ]
                         ip:10.1.2.10        2001:0:0:51::6
                                [ FIP ] : 10.10.10.13      0x3
                        [ vm14-veth1 ]
                         ip:10.1.2.11        2001:0:0:51::7
                                [ FIP ] : 10.10.10.14      0x3
            evpn_id: 52(0x34) GW: 20.0.0.254 GWv6: 2001:0:0:52::254
                        [ vm16-veth1 ]
                         ip:20.1.2.11        2001:0:0:52::9
                                [ FIP ] : 10.10.10.16      0x3
                        [ vm8-veth1 ]
                         ip:20.1.2.10        2001:0:0:52::8
                                [ FIP ] : 10.10.10.15      0x3
        vrf_id: 10(0xa)
            evpn_id: 101(0x65) GW: 20.0.0.254 GWv6: None
            evpn_id: 102(0x66) GW: 10.0.0.254 GWv6: None
```
## Things Missing
1. This infra does not configure uplinks & preferences etc, but can be easily extended to support that.
   After all its python script call.
2. IKE may not work.
3. This creates a standalone OVS vm, so test scenarios involving tunnel trafic between two OVS's cannot be verified currently.
4. Equivalent ofctl code is not present for all the openflow pdus.

## References
1. https://blog.scottlowe.org/2013/09/04/introducing-linux-network-namespaces
2. https://docs.pytest.org/en/latest
3. http://mininet.org/
