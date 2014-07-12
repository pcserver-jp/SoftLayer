#!/bin/bash

cat << 'EOF' | tee /etc/ssh/sshd_config
AddressFamily inet
Protocol 2
SyslogFacility AUTHPRIV
#PermitRootLogin without-password
#PermitRootLogin forced-commands-only
PermitRootLogin no
PubkeyAuthentication yes
RSAAuthentication no
RhostsRSAAuthentication no
HostbasedAuthentication no
PasswordAuthentication no
ChallengeResponseAuthentication no
KerberosAuthentication no
GSSAPIAuthentication no
UsePAM yes
AcceptEnv LANG LC_CTYPE LC_NUMERIC LC_TIME LC_COLLATE LC_MONETARY LC_MESSAGES
AcceptEnv LC_PAPER LC_NAME LC_ADDRESS LC_TELEPHONE LC_MEASUREMENT
AcceptEnv LC_IDENTIFICATION LC_ALL LANGUAGE
AcceptEnv XMODIFIERS
AllowAgentForwarding yes
AllowTcpForwarding yes
GatewayPorts no
X11Forwarding no
PermitTunnel no
Subsystem       sftp    /usr/libexec/openssh/sftp-server
UseDNS no
EOF

sed -i -e 's/^ENCRYPT_METHOD .*$/ENCRYPT_METHOD SHA512/' /etc/login.defs
sed -i -e '/^MD5_CRYPT_ENAB/d' /etc/login.defs
sed -i -e 's/^PASSWDALGORITHM=.*$/PASSWDALGORITHM=sha512/' /etc/sysconfig/authconfig
sed -i -e 's/md5/sha512/' /etc/pam.d/password-auth
sed -i -e 's/md5/sha512/' /etc/pam.d/password-auth-ac
sed -i -e 's/md5/sha512/' /etc/pam.d/system-auth
sed -i -e 's/md5/sha512/' /etc/pam.d/system-auth-ac

echo oracle | passwd --stdin root

echo '%wheel ALL=(ALL) NOPASSWD: ALL' | tee /etc/sudoers.d/wheel
groupadd -g 500 softlayer
useradd -g softlayer -G wheel -u 500 softlayer
echo oracle | passwd --stdin softlayer
chage -d 0 softlayer
cp -a .ssh /home/softlayer/
chown -R softlayer:softlayer /home/softlayer/.ssh

cat << 'EOF' | tee /etc/sysconfig/iptables
*filter
:INPUT   ACCEPT [0:0]
:FORWARD ACCEPT [0:0]
:OUTPUT  ACCEPT [0:0]
-A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
-A INPUT -i lo -j ACCEPT
########## Public VLAN (& Private VLAN) ##########
#ams01#-A INPUT -p icmp -s 159.253.158.0/23 -j ACCEPT
#dal01#-A INPUT -p icmp -s 66.228.118.0/23  -j ACCEPT
#dal05#-A INPUT -p icmp -s 173.192.118.0/23 -j ACCEPT
#dal06#-A INPUT -p icmp -s 184.172.118.0/23 -j ACCEPT
#dal07#-A INPUT -p icmp -s 50.22.118.0/23   -j ACCEPT
#hou02#-A INPUT -p icmp -s 173.193.118.0/23 -j ACCEPT
#hkg02#-A INPUT -p icmp -s 119.81.138.0/23  -j ACCEPT
#sea01#-A INPUT -p icmp -s 67.228.118.0/23  -j ACCEPT
#sjc01#-A INPUT -p icmp -s 50.23.118.0/23   -j ACCEPT
#sng01#-A INPUT -p icmp -s 174.133.118.0/23 -j ACCEPT
#wdc01#-A INPUT -p icmp -s 208.43.118.0/23  -j ACCEPT
-A INPUT -p icmp -s 119.81.138.0/23 -j ACCEPT
-A INPUT -p tcp -m state --state NEW -m tcp --dport 22 -j ACCEPT
#-A INPUT -i eth1  -j LOG --log-prefix "IPTABLES_DROP_GLOBAL : " --log-level=info
#-A INPUT -i eth3  -j LOG --log-prefix "IPTABLES_DROP_GLOBAL : " --log-level=info
#-A INPUT -i bond1 -j LOG --log-prefix "IPTABLES_DROP_GLOBAL : " --log-level=info
-A INPUT -i eth1  -j DROP
-A INPUT -i eth3  -j DROP
-A INPUT -i bond1 -j DROP
########## Private VLAN ##########
#hkg02#-A INPUT -p tcp -m state --state NEW -m tcp --dport 22 -s 10.2.216.0/24 -j ACCEPT
#tok01#-A INPUT -p tcp -m state --state NEW -m tcp --dport 22 -s 10.2.225.0/24 -j ACCEPT
-A INPUT -p tcp -m state --state NEW -m tcp --dport   80 -s 10.0.0.0/8 -j ACCEPT
-A INPUT -p tcp -m state --state NEW -m tcp --dport  443 -s 10.0.0.0/8 -j ACCEPT
-A INPUT -p tcp -m state --state NEW -m tcp --dport 3260 -s 10.0.0.0/8 -j ACCEPT
-A INPUT -p tcp -m state --state NEW -m tcp --dport   53 -s 10.0.0.0/8 -j ACCEPT
-A INPUT -p udp -m state --state NEW -m udp --dport   53 -s 10.0.0.0/8 -j ACCEPT
-A INPUT -p icmp                                         -s 10.0.0.0/8 -j ACCEPT
#-A INPUT -j LOG --log-prefix "IPTABLES_REJECT_PRIVATE : " --log-level=info
-A INPUT -j REJECT --reject-with icmp-host-prohibited
##########  ##########
-A FORWARD -j REJECT --reject-with icmp-host-prohibited
COMMIT
EOF
if ! ifconfig bond0 > /dev/null 2>&1; then
  sed -i -e '/bond0/d' /etc/sysconfig/iptables
  sed -i -e '/bond1/d' /etc/sysconfig/iptables
  sed -i -e '/eth2/d' /etc/sysconfig/iptables
  sed -i -e '/eth3/d' /etc/sysconfig/iptables
fi
chmod 600 /etc/sysconfig/iptables

sed -i -e 's/^keepcache=.*$/keepcache=1/' /etc/yum.conf
sed -i -e '/^assumeyes=.*$/d' /etc/yum.conf

yum -y update
yum -y install \
 apr \
 apr-util \
 apr-util-ldap \
 crypto-utils \
 db4-cxx \
 db4-devel \
 elinks \
 gd \
 gdbm-devel \
 glibc-devel \
 glibc-headers \
 httpd \
 httpd-manual \
 httpd-tools \
 ipmitool \
 kernel-headers \
 libXpm \
 lm_sensors-libs \
 mailcap \
 mod_perl \
 mod_ssl \
 mod_wsgi \
 net-snmp-libs \
 nss_compat_ossl \
 OpenIPMI \
 OpenIPMI-libs \
 perl-BSD-Resource \
 perl-devel \
 perl-ExtUtils-MakeMaker \
 perl-ExtUtils-ParseXS \
 perl-Newt \
 perl-Test-Harness \
 webalizer

/etc/init.d/ip6tables stop
sed -i -e '/^NOZEROCONF.*$/d'         /etc/sysconfig/network
sed -i -e '/^NETWORKING_IPV6.*$/d'    /etc/sysconfig/network
sed -i -e '/^IPV6INIT.*$/d'           /etc/sysconfig/network
sed -i -e '/^IPV6_AUTOCONF.*$/d'      /etc/sysconfig/network
sed -i -e '/^IPV4_FAILURE_FATAL.*$/d' /etc/sysconfig/network
cat << 'EOF' | tee -a /etc/sysconfig/network
NOZEROCONF=yes
NETWORKING_IPV6=no
IPV6INIT=no
IPV6_AUTOCONF=no
IPV4_FAILURE_FATAL=yes
EOF
sed -i -e '/^# Disable IPv6.*$/d'                     /etc/sysctl.conf
sed -i -e '/^net.ipv6.conf.all.disable_ipv6.*$/d'     /etc/sysctl.conf
sed -i -e '/^net.ipv6.conf.default.disable_ipv6.*$/d' /etc/sysctl.conf
cat << 'EOF' | tee -a /etc/sysctl.conf
# Disable IPv6
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
EOF

[ -e /etc/sysconfig/network-scripts/ifcfg-eth0  ] && sed -i -e '/^NM_CONTROLLED.*$/d' /etc/sysconfig/network-scripts/ifcfg-eth0
[ -e /etc/sysconfig/network-scripts/ifcfg-eth1  ] && sed -i -e '/^NM_CONTROLLED.*$/d' /etc/sysconfig/network-scripts/ifcfg-eth1
[ -e /etc/sysconfig/network-scripts/ifcfg-eth2  ] && sed -i -e '/^NM_CONTROLLED.*$/d' /etc/sysconfig/network-scripts/ifcfg-eth2
[ -e /etc/sysconfig/network-scripts/ifcfg-eth3  ] && sed -i -e '/^NM_CONTROLLED.*$/d' /etc/sysconfig/network-scripts/ifcfg-eth3
[ -e /etc/sysconfig/network-scripts/ifcfg-bond0 ] && sed -i -e '/^NM_CONTROLLED.*$/d' /etc/sysconfig/network-scripts/ifcfg-bond0
[ -e /etc/sysconfig/network-scripts/ifcfg-bond1 ] && sed -i -e '/^NM_CONTROLLED.*$/d' /etc/sysconfig/network-scripts/ifcfg-bond1
[ -e /etc/sysconfig/network-scripts/ifcfg-eth0  ] && echo 'NM_CONTROLLED=no' | tee -a /etc/sysconfig/network-scripts/ifcfg-eth0
[ -e /etc/sysconfig/network-scripts/ifcfg-eth1  ] && echo 'NM_CONTROLLED=no' | tee -a /etc/sysconfig/network-scripts/ifcfg-eth1
[ -e /etc/sysconfig/network-scripts/ifcfg-eth2  ] && echo 'NM_CONTROLLED=no' | tee -a /etc/sysconfig/network-scripts/ifcfg-eth2
[ -e /etc/sysconfig/network-scripts/ifcfg-eth3  ] && echo 'NM_CONTROLLED=no' | tee -a /etc/sysconfig/network-scripts/ifcfg-eth3
[ -e /etc/sysconfig/network-scripts/ifcfg-bond0 ] && echo 'NM_CONTROLLED=no' | tee -a /etc/sysconfig/network-scripts/ifcfg-bond0
[ -e /etc/sysconfig/network-scripts/ifcfg-bond1 ] && echo 'NM_CONTROLLED=no' | tee -a /etc/sysconfig/network-scripts/ifcfg-bond1

grep -q -v ^# /etc/cron.d/raid-check && sed -i -e 's/^/#/' /etc/cron.d/raid-check

cat << 'EOF' | tee /etc/sysconfig/clock
ZONE="Asia/Tokyo"
EOF
cp -a /usr/share/zoneinfo/Asia/Tokyo /etc/localtime

cat << 'EOF' | tee /etc/sysconfig/keyboard
KEYTABLE="jp106"
MODEL="jp106"
LAYOUT="jp"
KEYBOARDTYPE="pc"
EOF

yum -y install python-setuptools
easy_install softlayer

cat << 'EOF' | tee /home/softlayer/.softlayer
[softlayer]
username = SL999999
api_key = abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz01
endpoint_url = https://api.service.softlayer.com/xmlrpc/v3.1
timeout = 10
EOF
chmod 600 /home/softlayer/.softlayer
echo 'user = SL999999:abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz01' | tee /home/softlayer/.softlayer.user
chmod 600 /home/softlayer/.softlayer.user
chown softlayer:softlayer /home/softlayer/.softlayer*

mkdir /var/www/html/repo.nosig/

yum clean all
sed -i -e 's/^DEFAULTKERNEL=.*$/DEFAULTKERNEL=kernel-uek/' /etc/sysconfig/kernel
curl -O https://linux.oracle.com/switch/centos2ol.sh
yes | sh centos2ol.sh
mkdir /var/www/html/oracle/
mv centos2ol.sh /var/www/html/oracle/
mkdir /var/www/html/repo.ol6/
mv /var/cache/yum/x86_64/*/*/packages/*.rpm /var/www/html/repo.ol6/

groupadd -g 54321 oinstall
groupadd -g 54322 dba
groupadd -g 54323 oper
groupadd -g 54324 backupdba
groupadd -g 54325 dgdba
groupadd -g 54326 kmdba
groupadd -g 54327 asmadmin
groupadd -g 54328 asmdba
groupadd -g 54329 asmoper
useradd -g oinstall -G dba,backupdba,dgdba,kmdba,asmdba -u 54321 oracle
echo oracle | passwd --stdin oracle
useradd -g oinstall -G asmadmin,asmdba,asmoper -u 54322 grid
echo oracle | passwd --stdin grid

yum -y update
yum -y install         \
 kernel-uek            \
 kernel-uek-devel      \
 ntpdate               \
 createrepo            \
 iscsi-initiator-utils \
 scsi-target-utils     \
 perl-Authen-SASL      \
 perl-MIME-tools       \
 xterm                 \
 xorg-x11-apps         \
 tigervnc-server       \
 ipa-gothic-fonts      \
 ipa-mincho-fonts      \
 ipa-pgothic-fonts     \
 ipa-pmincho-fonts     \
 vlgothic-fonts        \
 vlgothic-p-fonts      \
 bind-utils            \
 compat-libcap1        \
 compat-libstdc++-33   \
 ksh                   \
 libaio-devel          \
 nfs-utils             \
 smartmontools         \
 sysstat               \
 systemtap-devel       \
 xinetd                \
 firefox               \
 reflink               \
 ocfs2-tools-devel     \
 oracleasm-support     \
 oracle-rdbms-server-12cR1-preinstall
yum -y groupinstall "X Window System" "Development tools" "Desktop"
mv /var/cache/yum/x86_64/*/*/packages/*.rpm /var/www/html/repo.ol6/

for i in $(chkconfig --list | grep ^[A-Za-z] | grep -v services: | awk '{print $1}')
do
  case $i in
    atd                   ) chkconfig $i on;;
    crond                 ) chkconfig $i on;;
    dnsmasq               ) chkconfig $i on;;
    httpd                 ) chkconfig $i on;;
    iptables              ) chkconfig $i on;;
    irqbalance            ) chkconfig $i on;;
    lvm2-monitor          ) chkconfig $i on;;
    network               ) chkconfig $i on;;
    ntpd                  ) chkconfig $i on;;
    rsyslog               ) chkconfig $i on;;
    sshd                  ) chkconfig $i on;;
    tgtd                  ) chkconfig $i on;;
    udev-post             ) chkconfig $i on;;
    xe-linux-distribution ) chkconfig $i on;;
    * ) chkconfig --level 0123456 $i off;;
  esac
done
[ -e /proc/xen ] && chkconfig --level 0123456 ntpd off

cat << 'EOF' | tee /etc/sysconfig/ntpd
# Drop root to id 'ntp:ntp' by default.
OPTIONS="-4 -x -u ntp:ntp -p /var/run/ntpd.pid -g"
EOF
cat << 'EOF' | tee /etc/ntp.conf
driftfile /var/lib/ntp/drift
restrict default kod nomodify notrap nopeer noquery
restrict 127.0.0.1
server -4 10.0.77.54 iburst
includefile /etc/ntp/crypto/pw
keys /etc/ntp/keys
EOF

cat << 'EOF' | tee /etc/sysconfig/vncservers
VNCSERVERS="1:softlayer"
VNCSERVERARGS[1]="-geometry 1024x768 -nolisten tcp -localhost"
EOF

mkdir /home/softlayer/.vnc
echo czhlMTYhpiU= | base64 -di | tee /home/softlayer/.vnc/passwd
chmod 600 /home/softlayer/.vnc/passwd
chown -R softlayer:softlayer /home/softlayer/.vnc

cat << 'EOF' | tee /etc/pki/tls/certs/server.key
-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEAt3OdtR7iguxXfpPyUaSw1sTbCaguGf2SVzmTwrLdHImc3Rc3
FAa1UrqANnqLYVNYDha9NGEI8o4WmAdq59HdNiBhg7VEx5+c8jpfB74fOtUm87Y5
Gb99PVR3FXGDuUbsNZKLuXRIhJfKsI7m4uekLpfy2xXvI8D/qPibATAQvVxxcDTp
gEoplAPe9SBxyxnUvj9/6c5cxK4WeLbN5jz4z5Sbjd0NOrEwuLjVNK19YvL0uZza
6EswdpcF+TonuZp1Ts8DAZioYjTTvYMNbd2jzOLHVUE4EknJRBb+iKM99JGObYf2
sRuECIWIYF76hd/Xq7eMi+6e9yDzCWYK9FbhuQIDAQABAoIBADqSEzwMjE04oAat
vaQLbNplJ3nB1FY/+0UWAPMcoDPIS+jazJ78NVAgc2bxYSbFsUtuPyJGCNFIRDZt
x9gTzQjG9dtTOI5zi2xa7pROQzJJc5JED58E4DuAiDS0dVXmKuw/yZSAZ9bNj80n
EthHFMg7gzInop5LtFSCaxrJ+c469vepIDuckglshxO8dGbW1G7ZSV5M7FBjnj4P
v1tRkpDh0+/ycNAKF/H2HnUKBJIsJYqo8OOaGig3ZkkSPaQIvh5mlYVeMIEqK4Nz
11eR5O+wOcCTjmNL8SB4J9pzZ6UPH2rj+IdlqNh2kVfBI6kS7n9z9Oj047chW4o7
OqFxKAECgYEA5L4CbYsvmUjG9rQbjMCjC7iP3iA52K/CejmFsVA9cG13FUqWZUQe
D0taJZIztHi5ImmFAMOwGC1W+BrZj1B3szB0g1ZcshxRkozT9lPcs6F3m0CFainR
f/jvmU5Sd8lrfT+DJ3JvJVfUQc2ywvBoqvh8JUyMQDuzTSzIfZGEynkCgYEAzU/5
t1xB4/SJGWKx5HZVwqO88NQ4hw0KwJaGDW0fav1k3hYsj/PlfsDVptYAsKOMlLaX
DNZQ1TYYlCbM9kv85u5iegqesrI0utUtBmuq8jSnZgPVaX/PS3EdaG0Gggotyywe
Hj141Yl/38XIm+G60EYqd0nVzxiLz4OPva49AUECgYA+dkRjdWaCDQWHyJbdUJ01
Tii7F0G0kgohJiQDz013reyeu8dlz7wFoSX0rH/CAFVNuFLBaq5ja74b8fkG0Ype
PBUU6DhXyrPbuOkIks3pn2Xx1ySXYOP8dhW3X1PVsgLQKM+/rdf78ofbkDgIU23B
gikkZkrGH4dOw7Pb1ijUwQKBgBOu5ibhDmQXTomDf8CCY8hsQDHqdpzj8DL0e1eQ
LaHpNyFfiNgoLslPHWyIObq1g0XCl4qghVFbhVG2wpGeSVmuYvyGRh6lnQ6IX2+t
JM9houbR2UTq/umhp4saYLRY23kN+rk1dX8rVnoSkR/4rRtIjsuu5XOcS9MSLtal
fK3BAoGAKO5k4V0ziORdRgpwLzI0lM6mUYqwyPhJtiy5wh+FUVB3kXbT5Z0O5LM8
u3y2xFE7x6/Y4YTd6n5oXqGzdLTAiZSog6Sxpf3wUcXXdXROCXGbbMlCNf674fQM
auihOVWl+VOFacunZ41/wj48AZlh2HOmTtaO5J0rCVXRy/agRjA=
-----END RSA PRIVATE KEY-----
EOF
cat << 'EOF' | tee /etc/pki/tls/certs/server.crt
-----BEGIN CERTIFICATE-----
MIIDPjCCAiYCCQDt0/++dOF3izANBgkqhkiG9w0BAQUFADBgMQswCQYDVQQGEwJK
UDENMAsGA1UECAwEQ2h1bzEOMAwGA1UEBwwFVG9reW8xFDASBgNVBAoMC2V4YW1w
bGUuY29tMRwwGgYDVQQDDBNpc2NzaTAxLmV4YW1wbGUuY29tMCAXDTE0MDcwOTIy
MjgzNVoYDzIxMTQwNjE1MjIyODM1WjBgMQswCQYDVQQGEwJKUDENMAsGA1UECAwE
Q2h1bzEOMAwGA1UEBwwFVG9reW8xFDASBgNVBAoMC2V4YW1wbGUuY29tMRwwGgYD
VQQDDBNpc2NzaTAxLmV4YW1wbGUuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A
MIIBCgKCAQEAt3OdtR7iguxXfpPyUaSw1sTbCaguGf2SVzmTwrLdHImc3Rc3FAa1
UrqANnqLYVNYDha9NGEI8o4WmAdq59HdNiBhg7VEx5+c8jpfB74fOtUm87Y5Gb99
PVR3FXGDuUbsNZKLuXRIhJfKsI7m4uekLpfy2xXvI8D/qPibATAQvVxxcDTpgEop
lAPe9SBxyxnUvj9/6c5cxK4WeLbN5jz4z5Sbjd0NOrEwuLjVNK19YvL0uZza6Esw
dpcF+TonuZp1Ts8DAZioYjTTvYMNbd2jzOLHVUE4EknJRBb+iKM99JGObYf2sRuE
CIWIYF76hd/Xq7eMi+6e9yDzCWYK9FbhuQIDAQABMA0GCSqGSIb3DQEBBQUAA4IB
AQCyONaQR8qwT8lhElI5WSPav7XA/WPpOnrm0yH5O6JSrlAraUzn/yHUBxqsQzKy
f876P+Y7paGZHyaCcy7QKoPA0SCbgQY3aWkJSRDBS1a8KNvG9PYHs4kbhtOjXH/L
oZU8WYgjUpgkrWyZSJdYX94e4IVOEtzyASHZWa3uH3iH233FsSjZjXc0tC94a3sp
0mMP36kPLfV311s9f1KXEPqpjFmsh3lltBcKfaXAGiw3UIh/UFaa16R8ME8Kj94Q
ORgzSb34hOaLbwQozYVCjpMhjIlamevOIWuosMK3QXAR9oLLGLuBv02Fvh1zoN7h
NpgcSNBAR0Mk4czf2yI8f9iP
-----END CERTIFICATE-----
EOF
chmod 400 /etc/pki/tls/certs/server.*

createrepo /var/www/html/repo.ol6/
createrepo /var/www/html/repo.nosig/
mkdir /var/www/html/norpms
createrepo /var/www/html/norpms/
NIC0=bond0; ifconfig bond0 > /dev/null 2>&1 || NIC0=eth0
PRIVATE_IP=$(ifconfig $NIC0 | grep 'inet addr' | awk '{print $2}' | awk -F: '{print $2}')
cat << EOF | tee /var/www/html/public-yum-ol6.repo
[public_ol6_latest]
name=Oracle Linux 6 Latest (x86_64)
baseurl=http://$PRIVATE_IP/repo.ol6/
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-oracle
gpgcheck=1
enabled=1

[public_ol6_addons]
name=Oracle Linux 6 Add ons (x86_64)
baseurl=http://$PRIVATE_IP/norpms/
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-oracle
gpgcheck=1
enabled=0

[public_ol6_ga_base]
name=Oracle Linux 6 GA installation media copy (x86_64)
baseurl=http://$PRIVATE_IP/norpms/
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-oracle
gpgcheck=1
enabled=0

[public_ol6_u1_base]
name=Oracle Linux 6 Update 1 installation media copy (x86_64)
baseurl=http://$PRIVATE_IP/norpms/
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-oracle
gpgcheck=1
enabled=0

[public_ol6_u2_base]
name=Oracle Linux 6 Update 2 installation media copy (x86_64)
baseurl=http://$PRIVATE_IP/norpms/
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-oracle
gpgcheck=1
enabled=0

[public_ol6_u3_base]
name=Oracle Linux 6 Update 3 installation media copy (x86_64)
baseurl=http://$PRIVATE_IP/norpms/
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-oracle
gpgcheck=1
enabled=0

[public_ol6_u4_base]
name=Oracle Linux 6 Update 4 installation media copy (x86_64)
baseurl=http://$PRIVATE_IP/norpms/
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-oracle
gpgcheck=1
enabled=0

[public_ol6_u5_base]
name=Oracle Linux 6 Update 5 installation media copy (x86_64)
baseurl=http://$PRIVATE_IP/norpms/
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-oracle
gpgcheck=1
enabled=0

[public_ol6_UEKR3_latest]
name=Latest Unbreakable Enterprise Kernel for Oracle Linux 6 (x86_64)
baseurl=http://$PRIVATE_IP/norpms/
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-oracle
gpgcheck=1
enabled=0

[public_ol6_UEK_latest]
name=Latest Unbreakable Enterprise Kernel for Oracle Linux 6 (x86_64)
baseurl=http://$PRIVATE_IP/repo.ol6/
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-oracle
gpgcheck=1
enabled=0

[public_ol6_UEK_base]
name=Unbreakable Enterprise Kernel for Oracle Linux 6 (x86_64)
baseurl=http://$PRIVATE_IP/norpms/
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-oracle
gpgcheck=1
enabled=0

[public_ol6_playground_latest]
name=Latest mainline stable kernel for Oracle Linux 6 (x86_64) - Unsupported
baseurl=http://$PRIVATE_IP/norpms/
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-oracle
gpgcheck=1
enabled=0

[public_ol6_MySQL]
name=MySQL 5.5 for Oracle Linux 6 (x86_64)
baseurl=http://$PRIVATE_IP/norpms/
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-oracle
gpgcheck=1
enabled=0

[public_ol6_gdm_multiseat]
name=Oracle Linux 6 GDM Multiseat (x86_64)
baseurl=http://$PRIVATE_IP/norpms/
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-oracle
gpgcheck=1
enabled=0

[public_ol6_ofed_UEK]
name=OFED supporting tool packages for Unbreakable Enterprise Kernel on Oracle Linux 6 (x86_64)
baseurl=http://$PRIVATE_IP/norpms/
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-oracle
gpgcheck=1
enabled=0

[public_ol6_MySQL56]
name=MySQL 5.6 for Oracle Linux 6 (x86_64)
baseurl=http://$PRIVATE_IP/norpms/
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-oracle
gpgcheck=1
enabled=0

[public_ol6_spacewalk20_server]
name=Spacewalk Server 2.0 for Oracle Linux 6 (x86_64)
baseurl=http://$PRIVATE_IP/norpms/
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-oracle
gpgcheck=1
enabled=0

[public_ol6_spacewalk20_client]
name=Spacewalk Client 2.0 for Oracle Linux 6 (x86_64)
baseurl=http://$PRIVATE_IP/norpms/
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-oracle
gpgcheck=1
enabled=0
EOF
cat << 'EOF' | tee /var/www/html/repo-with-no-sign.repo
[Repo with no sign]
name=Repo with no sign (x86_64)
baseurl=http://$PRIVATE_IP/repo.nosig/
gpgcheck=0
enabled=0
EOF

echo 'conf-dir=/etc/dnsmasq.d' | tee /etc/dnsmasq.conf
echo 'resolv-file=/etc/dnsmasq.resolv.conf' | tee /etc/dnsmasq.d/resolv.conf
cat << 'EOF' | tee /etc/dnsmasq.resolv.conf
nameserver 10.0.80.11
nameserver 10.0.80.12
EOF
cat << 'EOF' | tee /etc/resolv.conf
nameserver 127.0.0.1
options single-request
search example.com
EOF
sed -i -e 's/^hosts:.*$/hosts:      dns files/' /etc/nsswitch.conf

fdisk -H 64 -S 32 /dev/xvdc << 'EOF'
o
n
p
1


t
8e
p
w
EOF
pvcreate /dev/xvdc1
vgcreate -s 32M vg0 /dev/xvdc1
lvcreate -L 20480 -n u01 vg0
lvcreate -L 40960 -n u02 vg0
lvcreate -L 10240 -n u03 vg0
lvcreate -L 10240 -n u04 vg0
lvcreate -L 10240 -n u05 vg0
mkfs.ext4 -L /u01 /dev/vg0/u01
mkfs.ext4 -L /u02 /dev/vg0/u02
mkfs.ext4 -L /u03 /dev/vg0/u03
mkfs.ext4 -L /u04 /dev/vg0/u04
mkfs.ext4 -L /u05 /dev/vg0/u05
mkdir /u01 /u02 /u03 /u04 /u05
cat << 'EOF' | tee -a /etc/fstab
/dev/vg0/u01            /u01                    ext4    defaults,noatime 0 0
/dev/vg0/u02            /u02                    ext4    defaults,noatime 0 0
/dev/vg0/u03            /u03                    ext4    defaults,noatime 0 0
/dev/vg0/u04            /u04                    ext4    defaults,noatime 0 0
/dev/vg0/u05            /u05                    ext4    defaults,noatime 0 0
EOF
mount -a
mv /var/www /u01/
ln -s /u01/www /var/www
dd if=/dev/zero of=/u02/lun1 bs=1M count=0 seek=20480
dd if=/dev/zero of=/u02/lun2 bs=1M count=0 seek=20480
dd if=/dev/zero of=/u02/lun3 bs=1M count=0 seek=20480
dd if=/dev/zero of=/u03/lun4 bs=1M count=0 seek=102400
dd if=/dev/zero of=/u04/lun5 bs=1M count=0 seek=102400
dd if=/dev/zero of=/u05/lun6 bs=1M count=0 seek=102400
dd if=/dev/zero of=/u02/lun7 bs=1M count=0 seek=204800
dd if=/dev/zero of=/u02/lun8 bs=1M count=0 seek=204800
dd if=/dev/zero of=/u02/lun9 bs=1M count=0 seek=204800
cat << 'EOF' | tee /etc/tgt/targets.conf
<target iqn.2001-05.com.equallogic:0-8a0906-2ff8d0b0c-a5f00f70a42535b9-sli999999-1>
    backing-store /u02/lun1
    lun 1
    incominguser SLI999999-1 oracleoracle
    write-cache on
    scsi_id wwn-0x6090a0c8b0d0f82fb93525a4700ff0a1
    readonly 0
    allow-in-use yes
    MaxRecvDataSegmentLength 262144
    MaxXmitDataSegmentLength 65536
    InitialR2T No
</target>

<target iqn.2001-05.com.equallogic:0-8a0906-2ff8d0b0c-a5f00f70a42535b9-sli999999-2>
    backing-store /u02/lun2
    lun 1
    incominguser SLI999999-2 oracleoracle
    write-cache on
    scsi_id wwn-0x6090a0c8b0d0f82fb93525a4700ff0a2
    readonly 0
    allow-in-use yes
    MaxRecvDataSegmentLength 262144
    MaxXmitDataSegmentLength 65536
    InitialR2T No
</target>

<target iqn.2001-05.com.equallogic:0-8a0906-2ff8d0b0c-a5f00f70a42535b9-sli999999-3>
    backing-store /u02/lun3
    lun 1
    incominguser SLI999999-3 oracleoracle
    write-cache on
    scsi_id wwn-0x6090a0c8b0d0f82fb93525a4700ff0a3
    readonly 0
    allow-in-use yes
    MaxRecvDataSegmentLength 262144
    MaxXmitDataSegmentLength 65536
    InitialR2T No
</target>

<target iqn.2001-05.com.equallogic:0-8a0906-2ff8d0b0c-a5f00f70a42535b9-sli999999-4>
    backing-store /u03/lun4
    lun 1
    incominguser SLI999999-4 oracleoracle
    write-cache on
    scsi_id wwn-0x6090a0c8b0d0f82fb93525a4700ff0a4
    readonly 0
    allow-in-use yes
    MaxRecvDataSegmentLength 262144
    MaxXmitDataSegmentLength 65536
    InitialR2T No
</target>

<target iqn.2001-05.com.equallogic:0-8a0906-2ff8d0b0c-a5f00f70a42535b9-sli999999-5>
    backing-store /u04/lun5
    lun 1
    incominguser SLI999999-5 oracleoracle
    write-cache on
    scsi_id wwn-0x6090a0c8b0d0f82fb93525a4700ff0a5
    readonly 0
    allow-in-use yes
    MaxRecvDataSegmentLength 262144
    MaxXmitDataSegmentLength 65536
    InitialR2T No
</target>

<target iqn.2001-05.com.equallogic:0-8a0906-2ff8d0b0c-a5f00f70a42535b9-sli999999-6>
    backing-store /u05/lun6
    lun 1
    incominguser SLI999999-6 oracleoracle
    write-cache on
    scsi_id wwn-0x6090a0c8b0d0f82fb93525a4700ff0a6
    readonly 0
    allow-in-use yes
    MaxRecvDataSegmentLength 262144
    MaxXmitDataSegmentLength 65536
    InitialR2T No
</target>

<target iqn.2001-05.com.equallogic:0-8a0906-2ff8d0b0c-a5f00f70a42535b9-sli999999-7>
    backing-store /u02/lun7
    lun 1
    incominguser SLI999999-7 oracleoracle
    write-cache on
    scsi_id wwn-0x6090a0c8b0d0f82fb93525a4700ff0a7
    readonly 0
    allow-in-use yes
    MaxRecvDataSegmentLength 262144
    MaxXmitDataSegmentLength 65536
    InitialR2T No
</target>

<target iqn.2001-05.com.equallogic:0-8a0906-2ff8d0b0c-a5f00f70a42535b9-sli999999-8>
    backing-store /u02/lun8
    lun 1
    incominguser SLI999999-8 oracleoracle
    write-cache on
    scsi_id wwn-0x6090a0c8b0d0f82fb93525a4700ff0a8
    readonly 0
    allow-in-use yes
    MaxRecvDataSegmentLength 262144
    MaxXmitDataSegmentLength 65536
    InitialR2T No
</target>

<target iqn.2001-05.com.equallogic:0-8a0906-2ff8d0b0c-a5f00f70a42535b9-sli999999-9>
    backing-store /u02/lun9
    lun 1
    incominguser SLI999999-9 oracleoracle
    write-cache on
    scsi_id wwn-0x6090a0c8b0d0f82fb93525a4700ff0a9
    readonly 0
    allow-in-use yes
    MaxRecvDataSegmentLength 262144
    MaxXmitDataSegmentLength 65536
    InitialR2T No
</target>
EOF

reboot
