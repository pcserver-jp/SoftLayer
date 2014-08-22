#!/bin/bash

exec 2>&1

MY_DC=sjc01
MY_ROOT_PW=
MY_SL_ADMIN=sl-admin
MY_SL_ADMIN_PW=sl-admin
MY_SL_ADMIN_ID=65501

WHEEL_SUDO_NOPASSWD=yes
DISABLE_IPV6=yes

print_error_message_and_sleep()
{
  local R=$?
  if [ "$PS1" ]; then
    local E="###### Error "
    E="$E$E$E$E$E$E$E$E$E$E"
    echo "$E$E$E$E$E$E [$R] $*" 1>&2
    sleep 10
  else
    local E="###### Error [$R] $* #####"
    echo $E 1>&2
  fi
  ErrorCount=$((ErrorCount+1))
  return $R
}
Error=print_error_message_and_sleep

touch /etc/sudoers.d/wheel || $Error
chmod 640 /etc/sudoers.d/wheel || $Error
if [ "$WHEEL_SUDO_NOPASSWD" = "yes" ]; then
  echo '%wheel ALL=(ALL) NOPASSWD: ALL' | tee /etc/sudoers.d/wheel || $Error
else
  echo '%wheel ALL=(ALL) ALL'           | tee /etc/sudoers.d/wheel || $Error
fi

cp -a /etc/ssh/sshd_config /etc/ssh/sshd_config.org || $Error
cat << 'EOF' | tee /etc/ssh/sshd_config || $Error
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
/etc/init.d/sshd restart || $Error

touch /etc/sysconfig/iptables || $Error
chmod 600 /etc/sysconfig/iptables || $Error
cat << 'EOF' | tee /etc/sysconfig/iptables || $Error
*filter
:INPUT   ACCEPT [0:0]
:FORWARD ACCEPT [0:0]
:OUTPUT  ACCEPT [0:0]
-A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
-A INPUT -i lo -j ACCEPT
########## Public VLAN (& Private VLAN) ##########
-A INPUT -p icmp -s 119.81.138.0/23 -j ACCEPT
-A INPUT -i eth1  -j DROP
-A INPUT -i eth3  -j DROP
-A INPUT -i bond1 -j DROP
########## Private VLAN ##########
-A INPUT -p tcp --dport 22  -m tcp -m state --state NEW -s 10.2.216.0/24,10.2.225.0/24 -j ACCEPT
-A INPUT -p icmp                                        -s 10.0.0.0/8 -j ACCEPT
#-A INPUT -j LOG --log-prefix "IPTABLES_REJECT_PRIVATE : " --log-level=info
-A INPUT -j REJECT --reject-with icmp-host-prohibited
########## FORWARD ##########
-A FORWARD -j REJECT --reject-with icmp-host-prohibited
COMMIT
EOF
case $MY_DC in
  "ams01" ) sed -i -e 's/119\.81\.138/159.253.158/' -e 's/10\.2\.216/10.2.200/' /etc/sysconfig/iptables || $Error;;
  "dal01" ) sed -i -e 's/119\.81\.138/66.228.118/'  -e 's/10\.2\.216/10.1.0/'   /etc/sysconfig/iptables || $Error;;
  "dal05" ) sed -i -e 's/119\.81\.138/173.192.118/' -e 's/10\.2\.216/10.1.24/'  /etc/sysconfig/iptables || $Error;;
  "dal06" ) sed -i -e 's/119\.81\.138/184.172.118/' -e 's/10\.2\.216/10.2.208/' /etc/sysconfig/iptables || $Error;;
  "dal07" ) sed -i -e 's/119\.81\.138/50.22.118/'   -e 's/10\.2\.216/10.1.236/' /etc/sysconfig/iptables || $Error;;
  "hou02" ) sed -i -e 's/119\.81\.138/173.193.118/' -e 's/10\.2\.216/10.1.56/'  /etc/sysconfig/iptables || $Error;;
  "sea01" ) sed -i -e 's/119\.81\.138/67.228.118/'  -e 's/10\.2\.216/10.1.8.0/' /etc/sysconfig/iptables || $Error;;
  "sjc01" ) sed -i -e 's/119\.81\.138/50.23.118/'   -e 's/10\.2\.216/10.1.224/' /etc/sysconfig/iptables || $Error;;
  "sng01" ) sed -i -e 's/119\.81\.138/174.133.118/' -e 's/10\.2\.216/10.2.192/' /etc/sysconfig/iptables || $Error;;
  "wdc01" ) sed -i -e 's/119\.81\.138/208.43.118/'  -e 's/10\.2\.216/10.1.16/'  /etc/sysconfig/iptables || $Error;;
  "lon01" ) sed -i -e 's/119\.81\.138/5.10.118/'    -e 's/10\.2\.216/10.2.220/' /etc/sysconfig/iptables || $Error;;
esac
if ! ifconfig bond0 > /dev/null 2>&1; then
  sed -i -e '/bond0/d' /etc/sysconfig/iptables || $Error
  sed -i -e '/bond1/d' /etc/sysconfig/iptables || $Error
  sed -i -e '/eth2/d'  /etc/sysconfig/iptables || $Error
  sed -i -e '/eth3/d'  /etc/sysconfig/iptables || $Error
fi
/etc/init.d/iptables restart || $Error

if [ "$DISABLE_IPV6" = "yes" ]; then
  /etc/init.d/ip6tables stop || $Error
  cat << 'EOF' | tee -a /etc/sysconfig/network || $Error
NOZEROCONF=yes
NETWORKING_IPV6=no
IPV6INIT=no
IPV6_AUTOCONF=no
IPV4_FAILURE_FATAL=yes
EOF
  cat << 'EOF' | tee -a /etc/sysctl.conf || $Error

# Disable IPv6
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
EOF
  cat << 'EOF' | sudo tee /etc/modprobe.d/disable-ipv6.conf
options ipv6 disable=1
EOF
fi

cat << EOF | tee /etc/resolv.conf || $Error
nameserver 10.0.80.11
nameserver 10.0.80.12
options single-request
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

[ -e /etc/sysconfig/network-scripts/ifcfg-eth0  ] && echo 'ethtool --offload eth0 tx off sg off tso off gso off gro off' | tee -a /etc/rc.d/rc.local
[ -e /etc/sysconfig/network-scripts/ifcfg-eth1  ] && echo 'ethtool --offload eth1 tx off sg off tso off gso off gro off' | tee -a /etc/rc.d/rc.local
[ -e /etc/sysconfig/network-scripts/ifcfg-eth2  ] && echo 'ethtool --offload eth2 tx off sg off tso off gso off gro off' | tee -a /etc/rc.d/rc.local
[ -e /etc/sysconfig/network-scripts/ifcfg-eth3  ] && echo 'ethtool --offload eth3 tx off sg off tso off gso off gro off' | tee -a /etc/rc.d/rc.local

sed -i -e 's/^ENCRYPT_METHOD .*$/ENCRYPT_METHOD SHA512/' /etc/login.defs || $Error
sed -i -e '/^MD5_CRYPT_ENAB/d' /etc/login.defs || $Error
sed -i -e 's/^PASSWDALGORITHM=.*$/PASSWDALGORITHM=sha512/' /etc/sysconfig/authconfig || $Error
sed -i -e 's/md5/sha512/' /etc/pam.d/password-auth || $Error
sed -i -e 's/md5/sha512/' /etc/pam.d/password-auth-ac || $Error
sed -i -e 's/md5/sha512/' /etc/pam.d/system-auth || $Error
sed -i -e 's/md5/sha512/' /etc/pam.d/system-auth-ac || $Error
if [ "$MY_ROOT_PW" ]; then
  echo $MY_ROOT_PW | passwd --stdin root || $Error
else
  dd if=/dev/urandom bs=1 count=50 2> /dev/null | base64 | passwd --stdin root || $Error
fi

groupadd -g $MY_SL_ADMIN_ID $MY_SL_ADMIN || $Error
useradd -g $MY_SL_ADMIN -G wheel -u $MY_SL_ADMIN_ID $MY_SL_ADMIN || $Error
echo $MY_SL_ADMIN_PW | passwd --stdin $MY_SL_ADMIN || $Error
chage -d 0 $MY_SL_ADMIN || $Error
cp -a /root/.ssh /home/$MY_SL_ADMIN/ || $Error
chown -R $MY_SL_ADMIN:$MY_SL_ADMIN /home/$MY_SL_ADMIN/.ssh || $Error

cat << 'EOF' | tee /etc/sysconfig/clock || $Error
ZONE="Asia/Tokyo"
EOF
rm -f /etc/localtime || $Error
cp -a /usr/share/zoneinfo/Asia/Tokyo /etc/localtime || $Error

cat << 'EOF' | tee /etc/sysconfig/keyboard || $Error
KEYTABLE="jp106"
MODEL="jp106"
LAYOUT="jp"
KEYBOARDTYPE="pc"
EOF

sed -i -e '/^assumeyes=.*$/d' /etc/yum.conf || $Error

grep -q -v ^# /etc/cron.d/raid-check && sed -i -e 's/^/#/' /etc/cron.d/raid-check || $Error

for i in $(chkconfig --list | grep ^[A-Za-z] | grep -v services: | awk '{print $1}')
do
  chkconfig --del $i || $Error
  case $i in
    atd                   ) chkconfig --add $i || $Error; chkconfig $i on || $Error;;
    crond                 ) chkconfig --add $i || $Error; chkconfig $i on || $Error;;
    iptables              ) chkconfig --add $i || $Error; chkconfig $i on || $Error;;
    irqbalance            ) chkconfig --add $i || $Error; chkconfig $i on || $Error;;
    network               ) chkconfig --add $i || $Error; chkconfig $i on || $Error;;
    rsyslog               ) chkconfig --add $i || $Error; chkconfig $i on || $Error;;
    sshd                  ) chkconfig --add $i || $Error; chkconfig $i on || $Error;;
    udev-post             ) chkconfig --add $i || $Error; chkconfig $i on || $Error;;
    xe-linux-distribution ) chkconfig --add $i || $Error; chkconfig $i on || $Error;;
  esac
done
if [ ! -e /proc/xen ]; then
  chkconfig --add ntpd || $Error
  chkconfig ntpd on || $Error
  cat << 'EOF' | tee /etc/sysconfig/ntpd || $Error
# Drop root to id 'ntp:ntp' by default.
OPTIONS="-4 -x -u ntp:ntp -p /var/run/ntpd.pid -g"
EOF
  cat << 'EOF' | tee /etc/ntp.conf || $Error
driftfile /var/lib/ntp/drift
restrict default kod nomodify notrap nopeer noquery
restrict 127.0.0.1
server -4 10.0.77.54 iburst
includefile /etc/ntp/crypto/pw
keys /etc/ntp/keys
EOF
fi

reboot
