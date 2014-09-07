#!/bin/bash

exec 2>&1

MY_DC=dal06
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
    echo "###### Error [$R] $* #####" 1>&2
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
#net.ipv6.conf.all.disable_ipv6 = 1
#net.ipv6.conf.default.disable_ipv6 = 1
EOF
  cat << 'EOF' | tee /etc/modprobe.d/disable-ipv6.conf || $Error
options ipv6 disable=1
EOF
fi
sed -i -e 's/^net\.bridge/#net.bridge/' /etc/sysctl.conf || $Error

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

echo '/rescue/mk_offload_off' | tee -a /etc/rc.d/rc.local

sed -i -e 's/^default=0/default=0\nfallback=1/' /boot/grub/grub.conf || $Error
sed -i -e 's/^timeout=.*$/timeout=3/' /boot/grub/grub.conf || $Error
sed -i -e 's/^hiddenmenu/#hiddenmenu/' /boot/grub/grub.conf || $Error
sed -i -e 's/^splashimage/#splashimage/' /boot/grub/grub.conf || $Error
sed -i -e 's/biosdevname=0/biosdevname=0 selinux=0/g' /boot/grub/grub.conf || $Error
sed -i -e 's/console=hvc0/console=hvc0 biosdevname=0 selinux=0/g' /boot/grub/grub.conf || $Error
sed -i -e 's/ crashkernel=auto//g' /boot/grub/grub.conf || $Error
sed -i -e 's/ KEYBOARDTYPE=pc//g' /boot/grub/grub.conf || $Error
sed -i -e 's/ KEYTABLE=us//g' /boot/grub/grub.conf || $Error
sed -i -e 's/ LANG=en_US.UTF-8//g' /boot/grub/grub.conf || $Error
sed -i -e 's/ SYSFONT=latarcyrheb-sun16//g' /boot/grub/grub.conf || $Error
sed -i -e 's/ rhgb//g' /boot/grub/grub.conf || $Error
sed -i -e 's/ quiet//g' /boot/grub/grub.conf || $Error
sed -i -e '/^[^#]/ s/  / /g' /boot/grub/grub.conf || $Error
sed -i -e 's/biosdevname=0/biosdevname=0 crashkernel=auto KEYBOARDTYPE=pc KEYTABLE=106 LANG=en_US.UTF-8 SYSFONT=latarcyrheb-sun16 elevator=deadline/g' /boot/grub/grub.conf || $Error

wget -O /boot/vmlinuz http://mirrors.service.networklayer.com/centos/6/os/x86_64/isolinux/vmlinuz > /dev/null 2>&1 || $Error
wget -O /boot/initrd.img http://mirrors.service.networklayer.com/centos/6/os/x86_64/isolinux/initrd.img > /dev/null 2>&1 || $Error
NIC0=eth0
ifconfig bond0 > /dev/null 2>&1 && NIC0=bond0
cat << EOF | tee -a /boot/grub/grub.conf || $Error
title Rescue
^root (hd0,0)
^kernel /vmlinuz rescue repo=http://mirrors.service.networklayer.com/centos/6/os/x86_64/ lang=en_US keymap=jp106 selinux=0 sshd=1 nomount ksdevice=eth0 ip=$(ifconfig $NIC0 | grep inet | awk '{print $2}' | awk -F: '{print $2}') netmask=255.255.255.192 gateway=$(if route -n | grep -q '^10\.0\.0\.0'; then route -n | grep '^10\.0\.0\.0'; else route -n | grep '^0\.0\.0\.0'; fi | awk '{print $2}') dns=10.0.80.11
^initrd /initrd.img
EOF
sed -i -e 's/^^/\t/g' /boot/grub/grub.conf || $Error

ifconfig bond0 > /dev/null && mv /etc/modprobe.conf /etc/modprobe.d/bonding.conf 2> /dev/null

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

if grep -q ^CentOS /etc/system-release; then
  cat << 'EOF' | tee /etc/yum.repos.d/CentOS-Base.repo || $Error
[base]
name=CentOS-$releasever - Base
baseurl=http://mirrors.service.networklayer.com/centos/$releasever/os/$basearch/
gpgcheck=1
gpgkey=http://mirrors.service.networklayer.com/centos/RPM-GPG-KEY-CentOS-6
exclude=cluster-glue* corosync* heartbeat* ldirectord libesmtp* pacemaker* resource-agents* drbd*

[updates]
name=CentOS-$releasever - Updates
baseurl=http://mirrors.service.networklayer.com/centos/$releasever/updates/$basearch/
gpgcheck=1
gpgkey=http://mirrors.service.networklayer.com/centos/RPM-GPG-KEY-CentOS-6
exclude=cluster-glue* corosync* heartbeat* ldirectord libesmtp* pacemaker* resource-agents* drbd*

[extras]
name=CentOS-$releasever - Extras
baseurl=http://mirrors.service.networklayer.com/centos/$releasever/extras/$basearch/
gpgcheck=1
gpgkey=http://mirrors.service.networklayer.com/centos/RPM-GPG-KEY-CentOS-6

[centosplus]
name=CentOS-$releasever - Plus
baseurl=http://mirrors.service.networklayer.com/centos/$releasever/centosplus/$basearch/
gpgcheck=1
enabled=0
gpgkey=http://mirrors.service.networklayer.com/centos/RPM-GPG-KEY-CentOS-6

[contrib]
name=CentOS-$releasever - Contrib
baseurl=http://mirrors.service.networklayer.com/centos/$releasever/contrib/$basearch/
gpgcheck=1
enabled=0
gpgkey=http://mirrors.service.networklayer.com/centos/RPM-GPG-KEY-CentOS-6
EOF
fi

cat << 'EOF' | sudo tee /etc/yum.repos.d/epel.repo
[epel]
name=Extra Packages for Enterprise Linux 6 - $basearch
mirrorlist=https://mirrors.fedoraproject.org/metalink?repo=epel-6&arch=$basearch
failovermethod=priority
enabled=0
gpgcheck=1
gpgkey=http://ftp.riken.jp/Linux/fedora/epel/RPM-GPG-KEY-EPEL-6
exclude=cluster-glue* corosync* heartbeat* ldirectord libesmtp* pacemaker* resource-agents* drbd*
EOF

cat << 'EOF' | tee /etc/yum.repos.d/elrepo.repo || $Error
[elrepo]
name=ELRepo.org Community Enterprise Linux Repository - el6
baseurl=http://elrepo.org/linux/elrepo/el6/$basearch/
        http://mirrors.coreix.net/elrepo/elrepo/el6/$basearch/
        http://jur-linux.org/download/elrepo/elrepo/el6/$basearch/
        http://repos.lax-noc.com/elrepo/elrepo/el6/$basearch/
        http://mirror.ventraip.net.au/elrepo/elrepo/el6/$basearch/
mirrorlist=http://mirrors.elrepo.org/mirrors-elrepo.el6
enabled=0
gpgcheck=1
gpgkey=http://www.elrepo.org/RPM-GPG-KEY-elrepo.org
protect=0
EOF

mkdir /rescue || $Error

cat << 'EOF' | tee /rescue/mk_portable_ip || $Error
#!/bin/bash
if [ ! "$1" ]; then
  echo Usage: $0  new_portable_private_ip_address  [norestart]
  exit 1
fi
[ -e /proc/net/bonding ] && NIC0=bond0 || NIC0=eth0
NETWORK_123=$(echo $1 | awk -F. '{print $1 "." $2 "." $3}')
NETWORK_4=$(($(echo $1 | awk -F. '{print $4}')&~63))
GATEWAY="$NETWORK_123.$((NETWORK_4+1))"
sed -i -e "s/^IPADDR=.*\$/IPADDR=$1/" /etc/sysconfig/network-scripts/ifcfg-$NIC0
sed -i -e '/^GATEWAY=/d' /etc/sysconfig/network-scripts/ifcfg-$NIC0
sed -i -e "s%^10\\.0\\.0\\.0/8 via.*\$%10.0.0.0/8 via $GATEWAY%" /etc/sysconfig/network-scripts/route-$NIC0
[ "$2" = "norestart" ] || /etc/init.d/network restart
EOF
chmod 755 /rescue/mk_portable_ip || $Error

cat << 'EOF' | tee /rescue/mk_bond0
#!/bin/sh
ifconfig eth2 > /dev/null 2>&1 || exit 0
ifconfig bond0 > /dev/null 2>&1 && exit 0
IP=$(ifconfig eth0 | grep inet | awk '{print $2}' | awk -F: '{print $2}')
GATEWAY=$(if route -n | grep -q '^10\.0\.0\.0'; then route -n | grep '^10\.0\.0\.0'; else route -n | grep '^0\.0\.0\.0'; fi | awk '{print $2}')
modprobe bonding
#echo +bond0 > /sys/class/net/bonding_masters
ifconfig bond0 down
echo 4 > /sys/class/net/bond0/bonding/mode
echo 100 > /sys/class/net/bond0/bonding/miimon
echo fast > /sys/class/net/bond0/bonding/lacp_rate
echo 1 > /sys/class/net/bond0/bonding/xmit_hash_policy
ifconfig eth0 down; \
ifconfig eth2 down; \
ifconfig bond0 $IP netmask 255.255.255.192 up mtu 9000; \
echo +eth0 > /sys/class/net/bond0/bonding/slaves; \
echo +eth2 > /sys/class/net/bond0/bonding/slaves; \
route add -net 0.0.0.0/0 gw $GATEWAY
EOF
chmod 755 /rescue/mk_bond0

cat << 'EOF' | tee /rescue/mk_secure
#!/bin/sh
ifconfig bond1 down > /dev/null 2>&1
ifconfig eth1 down > /dev/null 2>&1
ifconfig eth3 down > /dev/null 2>&1
/etc/init.d/sshd stop > /dev/null 2>&1
kill -KILL $(ps -ef | grep [s]shd | grep anaconda | awk '{print $2}') > /dev/null 2>&1
EOF
chmod 755 /rescue/mk_secure

cat << 'EOF' | tee /rescue/mount
#!/bin/sh
mkdir -p /backup
[ "$1" ] || mount -t nfs $1:/backup /backup
[ -e /proc/xen ] && DEV=xvda || DEV=sda
mount -o rw,remount /dev/${DEV}2 /mnt/sysimage/
mount /dev/${DEV}1 /mnt/sysimage/boot
[ "$2" = "all" ] || exit 0
mount -t proc /proc /mnt/sysimage/proc
mount -t sysfs /sys /mnt/sysimage/sys
mount --bind /dev /mnt/sysimage/dev
EOF
chmod 755 /rescue/mount

cat << 'EOF' | tee /rescue/unmount
#!/bin/sh
umount /mnt/sysimage/dev
umount /mnt/sysimage/sys
umount /mnt/sysimage/proc
umount /mnt/sysimage/boot
[ -e /proc/xen ] && DEV=xvda || DEV=sda
mount -o ro,remount /dev/${DEV}2 /mnt/sysimage/
umount /backup
EOF
chmod 755 /rescue/unmount

cat << 'EOF' | tee /rescue/mk_offload_off || $Error
for i in eth0 eth1 eth2 eth3 bond0 bond1
do
  ifconfig $i > /dev/null 2>&1 || continue
  echo "[$i]"
  for j in rx tx sg tso ufo gso gro lro rxvlan txvlan ntuple rxhash
  do
    ethtool --offload $i $j off 2> /dev/null
  done
  ethtool --show-offload $i
done
EOF
chmod 755 /rescue/mk_offload_off || $Error

cat << 'EOF' | tee /rescue/reboot || $Error
#!/bin/bash
if [ -e /proc/xen ]; then
  sed -i -e 's/^\(default=.*\)$/##rescue##\1\ndefault=2/' /boot/grub/grub.conf && reboot
else
  kexec -l /boot/vmlinuz --initrd=/boot/initrd.img --command-line="rescue repo=http://mirrors.service.networklayer.com/centos/6.5/os/x86_64/ lang=en_US keymap=jp106 selinux=0 sshd=1 nomount ksdevice=eth0 ip=$(ifconfig $(ifconfig bond0 > /dev/null 2>&1 && echo bond0 || echo eth0) | grep inet | awk '{print $2}' | awk -F: '{print $2}') netmask=255.255.255.192 gateway=$(if route -n | grep -q '^10\.0\.0\.0'; then route -n | grep '^10\.0\.0\.0'; else route -n | grep '^0\.0\.0\.0'; fi | awk '{print $2}') dns=$(grep ^nameserver /etc/resolv.conf | head -1 | awk '{print $2}') mtu=9000 $@" && reboot
fi
EOF
chmod 755 /rescue/reboot || $Error

cat << 'EOF' | tee /usr/local/sbin/reboot_quick || $Error
#!/bin/bash
if [ ! -e /proc/xen ]; then
  LINE=$(grep ^default= /boot/grub/grub.conf | sed 's/default=//')
  KVER=$(grep -v ^# /boot/grub/grub.conf | grep vmlinuz- | sed 's/^.*vmlinuz-\([^ ]*\) .*$/\1/' | head -$((LINE+1)) | tail -1)
  CMDLINE="$(grep -v ^# /boot/grub/grub.conf | grep vmlinuz- | sed 's/^.*vmlinuz-\([^ ]* \)\(.*\)$/\2/' | head -$((LINE+1)) | tail -1) $@"
  /sbin/kexec -l /boot/vmlinuz-$KVER --initrd=/boot/initramfs-$KVER.img --command-line="$CMDLINE"
fi
/sbin/reboot
EOF
chmod 755 /usr/local/sbin/reboot_quick || $Error

/usr/local/sbin/reboot_quick || $Error
