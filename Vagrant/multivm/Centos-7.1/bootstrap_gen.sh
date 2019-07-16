#!/usr/bin/env bash

yum update
mkdir /usr/global/
mkdir -p /run/lock
kernel_version=$1
{
 echo "[nuage-centos-7.1-server-mirror]"
 echo "name=nuage-centos-7.1-mirror"
 echo "baseurl=http://mirrors.mv.nuagenetworks.net/rhel-7.1/rhel-7-server-eus-rpms/"
 echo "gpgcheck=0"
 echo "enabled=1"
} > /etc/yum.repos.d/nuage-el7.1-mirror.repo
echo "VagrantCentos7.1" > /etc/hostname
{
 echo "export OVS_RUNDIR=/var/run/openvswitch"
 export PATH=$PATH:$HOME/bin:/usr/local/bin:/usr/local/git/bin:/usr/local/gib/bin
} >> /root/.bash_profile
yum -y install epel-release
yum -y install python-docutils uuid kernel-$kernel_version.el7.x86_64 \
       tcpdump iptables-devel \
       protobuf-c-devel go nfs-utils cscope vim wget openssl-devel \
       gcc make python-devel openssl-devel autoconf automake rpm-build \
       redhat-rpm-config libtool libxml2-devel iproute cryptsetup golang \
       libvirt libvirt-devel kernel-devel-$kernel_version.el7.x86_64 \
       kernel-headers-$kernel_version.el7.x86_64 perl-Sys-Syslog python-ipaddr \
       python-lxml pytest python-pip vim tmux python-six perl\(JSON\) \
       python-setproctitle python-twisted-core conntrack gcc-c++ libgcrypt-devel \
       jsoncpp-devel gperftools pprof hping3 libpcap libpcap-devel docker glib*\
       perl-devel expect ntp yasm docker ipset redis libcap-ng-devel \
       hiredis-devel libcurl-devel yum-utils npm nodejs curl-devel pciutils watchdog
yum clean all
yum groupinstall "Development Tools"
yum install gettext-devel openssl-devel perl-CPAN perl-devel zlib-devel
yum-config-manager --add-repo https://www.nasm.us/nasm.repo
yum-config-manager --enable  nasm
yum -y install nasm
systemctl enable ntpd
systemctl start ntpd
service docker start
{
 echo "driftfile /var/lib/ntp/drift"
 echo "restrict default nomodify notrap nopeer noquery"
 echo "restrict 127.0.0.1"
 echo "restrict ::1"
 echo "server 0.centos.pool.ntp.org iburst"
 echo "server 1.centos.pool.ntp.org iburst"
 echo "server 2.centos.pool.ntp.org iburst"
 echo "server 3.centos.pool.ntp.org iburst"
 echo "includefile /etc/ntp/crypto/pw"
 echo "keys /etc/ntp/keys"
} > /etc/ntp.conf
ntpq -p

echo "=========== Git Config ==========="
cd /tmp
wget https://github.com/git/git/archive/v2.11.2.tar.gz -O git.tar.gz
tar -zxf git.tar.gz
cd git-*
make configure
./configure --prefix=/usr/local
make install
yum -y remove git
source /root/.bash_profile
git --version
echo $PATH
echo "=========== Git Config: Done ==========="

echo "=========== Pytest Config ==========="
pip install --upgrade pip
pip install -U pytest
pip install --user tmuxp
pip install pytest-spec
pip install pytest-instafail
pip install pytest-ordering
pip install pytest-logging
echo "=========== Pytest Config Done ==========="


echo "=========== Iptables Enable TRACE ==========="
modprobe nf_log_ipv4
sysctl net.netfilter.nf_log.2=nf_log_ipv4
echo "=========== Iptables Enable TRACE Done ==========="

{
 echo "strato.us.alcatel-lucent.com:/usr_global /usr/global            nfs    exec,dev,suid,rw              1       1"
} >> /etc/fstab
mount -a
cd /tmp
git clone https://github.com/larsks/python-netns
cd /tmp/python-netns && sudo python setup.py install
pip install --upgrade pip
pip uninstall scapy
pip install scapy
