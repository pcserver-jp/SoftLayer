#!/bin/bash

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

if ! grep -q ^ssh- /root/.ssh/authorized_keys; then
  $Error : no sshkey
  exit 1
fi

exec > /root/post_install.log || $Error
exec 2>&1 || $Error
set -x || $Error

#http://knowledgelayer.softlayer.com/faq/what-ip-ranges-do-i-allow-through-firewall
MY_DC=$(grep ^ssh- /root/.ssh/authorized_keys | head -1 |
  sed -e 's/^ssh-[^ ]* [^ ]* \(.*@\([a-z0-9]*\)\)$/\2/')
case "$MY_DC" in
  "ams01" ) :;;
  "dal01" ) :;;
  "dal05" ) :;;
  "dal06" ) :;;
  "dal07" ) :;;
  "hkg02" ) :;;
  "hou02" ) :;;
  "lon01" ) :;;
  "lon02" ) MY_DC=lon01;;
  "mel01" ) :;;
  "sea01" ) :;;
  "sjc01" ) :;;
  "sng01" ) :;;
  "tor01" ) :;;
  "wdc01" ) :;;
  * ) MY_DC=hkg02;;
esac || $Error

MY_ROOT_PW=
MY_SL_ADMIN=sl-admin
MY_SL_ADMIN_PW=sl-admin
MY_SL_ADMIN_ID=65501
WHEEL_SUDO_NOPASSWD=yes

ifconfig bond0 2> /dev/null && NIC0=bond0 || NIC0=eth0
IP0=$(ifconfig $NIC0 | grep inet | awk '{print $2}' | awk -F: '{print $2}')
NETMASK0=255.255.255.192
GATEWAY0=$(if route -n | grep -q '^10\.0\.0\.0'; then route -n | grep '^10\.0\.0\.0'; else route -n | grep '^0\.0\.0\.0'; fi | awk '{print $2}')
DNS0=10.0.80.11

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
#/etc/init.d/sshd restart || $Error

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
  "ams01" ) sed -i -e 's/119\.81\.138/159.253.158/' -e 's/10\.2\.216/10.2.200/'  /etc/sysconfig/iptables || $Error;;
  "dal01" ) sed -i -e 's/119\.81\.138/66.228.118/'  -e 's/10\.2\.216/10.1.0.0\/24,10.1.2/' /etc/sysconfig/iptables || $Error;;
  "dal05" ) sed -i -e 's/119\.81\.138/173.192.118/' -e 's/10\.2\.216/10.1.24/'   /etc/sysconfig/iptables || $Error;;
  "dal06" ) sed -i -e 's/119\.81\.138/184.172.118/' -e 's/10\.2\.216/10.2.208/'  /etc/sysconfig/iptables || $Error;;
  "dal07" ) sed -i -e 's/119\.81\.138/50.22.118/'   -e 's/10\.2\.216/10.1.236/'  /etc/sysconfig/iptables || $Error;;
# "hkg02" ) sed -i -e 's/119\.81\.138/119.81.138/'  -e 's/10\.2\.216/10.2.216/'  /etc/sysconfig/iptables || $Error;;
  "hou02" ) sed -i -e 's/119\.81\.138/173.193.118/' -e 's/10\.2\.216/10.1.56/'   /etc/sysconfig/iptables || $Error;;
  "lon01" ) sed -i -e 's/119\.81\.138/5.10.118/'    -e 's/10\.2\.216/10.2.220/'  /etc/sysconfig/iptables || $Error;;
  "mel01" ) sed -i -e 's/119\.81\.138/168.1.118/'    -e 's/10\.2\.216/10.2.228/' /etc/sysconfig/iptables || $Error;;
  "sea01" ) sed -i -e 's/119\.81\.138/67.228.118/'  -e 's/10\.2\.216/10.1.8.0/'  /etc/sysconfig/iptables || $Error;;
  "sjc01" ) sed -i -e 's/119\.81\.138/50.23.118/'   -e 's/10\.2\.216/10.1.224/'  /etc/sysconfig/iptables || $Error;;
  "sng01" ) sed -i -e 's/119\.81\.138/174.133.118/' -e 's/10\.2\.216/10.2.192/'  /etc/sysconfig/iptables || $Error;;
  "tor01" ) sed -i -e 's/119\.81\.138/158.85.118/'  -e 's/10\.2\.216/10.1.232/'  /etc/sysconfig/iptables || $Error;;
  "wdc01" ) sed -i -e 's/119\.81\.138/208.43.118/'  -e 's/10\.2\.216/10.1.16/'   /etc/sysconfig/iptables || $Error;;
esac
if ! ifconfig bond0 2> /dev/null; then
  sed -i -e '/bond0/ s/^/#/' /etc/sysconfig/iptables || $Error
  sed -i -e '/bond1/ s/^/#/' /etc/sysconfig/iptables || $Error
  sed -i -e '/eth2/  s/^/#/' /etc/sysconfig/iptables || $Error
  sed -i -e '/eth3/  s/^/#/' /etc/sysconfig/iptables || $Error
fi
/etc/init.d/iptables restart || $Error

if grep -q '^NOZEROCONF' /etc/sysconfig/network; then
  cat << 'EOF' | tee -a /etc/sysconfig/network || $Error
NOZEROCONF=yes
NETWORKING_IPV6=no
IPV6INIT=no
IPV6_AUTOCONF=no
IPV4_FAILURE_FATAL=yes
EOF
fi
if ! grep -q '^# Disable IPv6$' /etc/sysctl.conf; then
  cat << 'EOF' | tee -a /etc/sysctl.conf || $Error

# Disable IPv6
#net.ipv6.conf.all.disable_ipv6 = 1
#net.ipv6.conf.default.disable_ipv6 = 1
EOF
fi
cat << 'EOF' | tee /etc/modprobe.d/disable-ipv6.conf || $Error
options ipv6 disable=1
EOF
#  /etc/init.d/ip6tables stop || $Error

sed -i -e 's/^net\.bridge/#net.bridge/' /etc/sysctl.conf || $Error

cat << EOF | tee /etc/resolv.conf || $Error
nameserver 10.0.80.11
nameserver 10.0.80.12
options single-request
EOF

if [ -e /etc/sysconfig/network-scripts/ifcfg-eth0  ]; then
  sed -i -e '/^NM_CONTROLLED.*$/d' /etc/sysconfig/network-scripts/ifcfg-eth0 || $Error
  echo 'NM_CONTROLLED=no' | tee -a /etc/sysconfig/network-scripts/ifcfg-eth0 || $Error
fi
if [ -e /etc/sysconfig/network-scripts/ifcfg-eth1  ]; then
  sed -i -e '/^NM_CONTROLLED.*$/d' /etc/sysconfig/network-scripts/ifcfg-eth1 || $Error
  echo 'NM_CONTROLLED=no' | tee -a /etc/sysconfig/network-scripts/ifcfg-eth1 || $Error
fi
if [ -e /etc/sysconfig/network-scripts/ifcfg-eth2  ]; then
  sed -i -e '/^NM_CONTROLLED.*$/d' /etc/sysconfig/network-scripts/ifcfg-eth2 || $Error
  echo 'NM_CONTROLLED=no' | tee -a /etc/sysconfig/network-scripts/ifcfg-eth2 || $Error
fi
if [ -e /etc/sysconfig/network-scripts/ifcfg-eth3  ]; then
  sed -i -e '/^NM_CONTROLLED.*$/d' /etc/sysconfig/network-scripts/ifcfg-eth3 || $Error
  echo 'NM_CONTROLLED=no' | tee -a /etc/sysconfig/network-scripts/ifcfg-eth3 || $Error
fi
if [ -e /etc/sysconfig/network-scripts/ifcfg-bond0 ]; then
  sed -i -e '/^NM_CONTROLLED.*$/d' /etc/sysconfig/network-scripts/ifcfg-bond0 || $Error
  echo 'NM_CONTROLLED=no' | tee -a /etc/sysconfig/network-scripts/ifcfg-bond0 || $Error
fi
if [ -e /etc/sysconfig/network-scripts/ifcfg-bond1 ]; then
  sed -i -e '/^NM_CONTROLLED.*$/d' /etc/sysconfig/network-scripts/ifcfg-bond1 || $Error
  echo 'NM_CONTROLLED=no' | tee -a /etc/sysconfig/network-scripts/ifcfg-bond1 || $Error
fi
sed -i -e '/^MTU=/d' /etc/sysconfig/network-scripts/ifcfg-$NIC0 || $Error
if [ ! -d /proc/xen/ ]; then
  echo "MTU=9000" | tee -a /etc/sysconfig/network-scripts/ifcfg-$NIC0 || $Error
fi

if ! grep -q '^/rescue/mk_offload_off$' /etc/rc.d/rc.local; then
  echo '/rescue/mk_offload_off' | tee -a /etc/rc.d/rc.local || $Error
  echo '[ -x /rescue/once ] && /rescue/once' | tee -a /etc/rc.d/rc.local || $Error
fi

if ! grep -q ' selinux=0 ' /boot/grub/grub.conf; then
  wget -O /boot/vmlinuz http://mirrors.service.networklayer.com/centos/6.5/os/x86_64/isolinux/vmlinuz || $Error
  wget -O /boot/initrd.img http://mirrors.service.networklayer.com/centos/6.5/os/x86_64/isolinux/initrd.img || $Error
  sed -i -e 's/^default=0/default=0\nfallback=1/' /boot/grub/grub.conf || $Error
  sed -i -e 's/^timeout=.*$/timeout=3/' /boot/grub/grub.conf || $Error
#  sed -i -e 's/^hiddenmenu/#hiddenmenu/' /boot/grub/grub.conf || $Error
  sed -i -e 's/^splashimage/#splashimage/' /boot/grub/grub.conf || $Error
  sed -i -e 's/console=hvc0/console=hvc0 backup= biosdevname=0/g' /boot/grub/grub.conf || $Error
  sed -i -e 's/ crashkernel=auto//g' /boot/grub/grub.conf || $Error
  sed -i -e 's/ KEYBOARDTYPE=pc//g' /boot/grub/grub.conf || $Error
  sed -i -e 's/ KEYTABLE=us//g' /boot/grub/grub.conf || $Error
  sed -i -e 's/ LANG=en_US.UTF-8//g' /boot/grub/grub.conf || $Error
  sed -i -e 's/ SYSFONT=latarcyrheb-sun16//g' /boot/grub/grub.conf || $Error
  sed -i -e 's/ rd_NO_LUKS//g' /boot/grub/grub.conf || $Error
  sed -i -e 's/ rd_NO_LVM//g' /boot/grub/grub.conf || $Error
  sed -i -e 's/ rd_NO_MD//g' /boot/grub/grub.conf || $Error
  sed -i -e 's/ rd_NO_DM//g' /boot/grub/grub.conf || $Error
  sed -i -e 's/ rhgb//g' /boot/grub/grub.conf || $Error
  sed -i -e 's/ quiet//g' /boot/grub/grub.conf || $Error
  sed -i -e '/^[^#]/ s/  / /g' /boot/grub/grub.conf || $Error
  sed -i -e 's/biosdevname=0/biosdevname=0 selinux=0 crashkernel=auto KEYBOARDTYPE=pc KEYTABLE=106 LANG=en_US.UTF-8 SYSFONT=latarcyrheb-sun16 rd_NO_LUKS rd_NO_LVM rd_NO_MD rd_NO_DM elevator=deadline/g' /boot/grub/grub.conf || $Error
#  if [ ! -d /proc/xen/ ]; then
#    sed -i -e 's/ biosdevname=0/ biosdevname=0 console=tty0 console=ttyS1,19200n8r/g' /boot/grub/grub.conf || $Error
#    sed -i -e 's%^hiddenmenu%#hiddenmenu\nserial --unit=1 --speed=19200 --word=8 --parity=no --stop=1\nterminal --timeout=5 serial console%' /boot/grub/grub.conf || $Error
#  fi
  if ! grep -q ' rescue ' /boot/grub/grub.conf; then
    cat << EOF | tee -a /boot/grub/grub.conf || $Error
title Rescue
^root (hd0,0)
^kernel /vmlinuz rescue repo=http://mirrors.service.networklayer.com/centos/6/os/x86_64/ lang=en_US keymap=jp106 selinux=0 biosdevname=0 nomount sshd=1 ksdevice=eth0 ip=$IP0 netmask=$GATEWAY0 gateway=$GATEWAY0 dns=$DNS0
^initrd /initrd.img
EOF
    sed -i -e 's/^^/\t/g' /boot/grub/grub.conf || $Error
    if [ -d /proc/xen/ ]; then
      sed -i -e 's/ nomount/ console=hvc0 nomount/g' /boot/grub/grub.conf || $Error
    else
      sed -i -e 's/ nomount/ nomodeset pcie_aspm=off nomount/g' /boot/grub/grub.conf || $Error
    fi
  fi
  if [ -d /proc/xen/ ]; then
    cat << 'EOF' | tee /etc/sysconfig/grub || $Error
boot=/dev/xvda
forcelba=0
EOF
  else
    cat << 'EOF' | tee /etc/sysconfig/grub || $Error
boot=/dev/sda
forcelba=0
EOF
  fi
#/etc/securetty
fi
echo 'id:3:initdefault:' | tee /etc/inittab || $Error

if [ -e /etc/modprobe.conf ]; then
  mv /etc/modprobe.conf /etc/modprobe.d/bonding.conf || $Error
fi

cat << 'EOF' | tee /etc/modprobe.d/ixgbe.conf || $Error
options ixgbe IntMode=1,1
EOF

cat << 'EOF' | tee /etc/modprobe.d/anaconda.conf || $Error
# Module options and blacklists written by anaconda
options floppy allowed_drive_mask=0
EOF

rm -rf /etc/multipath/ || $Error

sed -i -e 's/^ENCRYPT_METHOD .*$/ENCRYPT_METHOD SHA512/' /etc/login.defs || $Error
sed -i -e '/^MD5_CRYPT_ENAB/d' /etc/login.defs || $Error
sed -i -e 's/^PASSWDALGORITHM=.*$/PASSWDALGORITHM=sha512/' /etc/sysconfig/authconfig || $Error
sed -i -e 's/md5/sha512/' /etc/pam.d/password-auth || $Error
sed -i -e 's/md5/sha512/' /etc/pam.d/password-auth-ac || $Error
sed -i -e 's/md5/sha512/' /etc/pam.d/system-auth || $Error
sed -i -e 's/md5/sha512/' /etc/pam.d/system-auth-ac || $Error

if ! id $MY_SL_ADMIN; then
  groupadd -g $MY_SL_ADMIN_ID $MY_SL_ADMIN || $Error
  useradd -g $MY_SL_ADMIN -G wheel -u $MY_SL_ADMIN_ID $MY_SL_ADMIN || $Error
  echo $MY_SL_ADMIN_PW | passwd --stdin $MY_SL_ADMIN || $Error
  chage -d 0 $MY_SL_ADMIN || $Error
  cp -a /root/.ssh /home/$MY_SL_ADMIN/ || $Error
  chown -R $MY_SL_ADMIN:$MY_SL_ADMIN /home/$MY_SL_ADMIN/.ssh || $Error
fi

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

sed -i -e '/^assumeyes=.*$/d' -e '/^failovermethod=.*$/d' -e 's/^installonly_limit=.*$/installonly_limit=3/' /etc/yum.conf || $Error

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
  rm -rf /etc/yum.repos.d/CentOS-Base.repo.orig* || $Error
fi

cat << 'EOF' | tee /etc/yum.repos.d/epel.repo || $Error
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

yum -y update || $Error

if [ -d /proc/xen/ ]; then
  yum -y install OpenIPMI ipmitool net-snmp-libs ntp iscsi-initiator-utils || $Error
else
  yum -y remove apr autoconf bind-devel cyrus-sasl-devel db4-cxx expat-devel libc-client mailcap php-common tcl || $Error
  yum -y localinstall https://raw.githubusercontent.com/pcserver-jp/SoftLayer/master/{xe-guest-utilities-6.2.0-1137.x86_64.rpm,xe-guest-utilities-xenstore-6.2.0-1137.x86_64.rpm} || $Error
fi

if [ ! -e /usr/local/sbin/ipmicli ]; then
  wget -O /usr/local/sbin/ipmicli http://downloads.service.softlayer.com/ipmi/linux/cli/ipmicli.x86_64 || $Error
  chmod 755 /usr/local/sbin/ipmicli || $Error
fi

if [ ! -d /usr/Adaptec_Event_Monitor/ ]; then
  wget http://download.adaptec.com/raid/storage_manager/adaptec_event_monitor_v1_06_21062.zip || $Error
  unzip adaptec_event_monitor_v1_06_21062.zip || $Error
  yum -y localinstall https://raw.githubusercontent.com/pcserver-jp/SoftLayer/master/kmod-aacraid-1.2.1-2.el6.x86_64.rpm linux_x64/EventMonitor-1.06-21062.x86_64.rpm || $Error
  rm -rf adaptec_event_monitor_v1_06_21062.zip debian debian_x64 freebsd* linux linux_x64 solaris_x86 windows* || $Error
  cat << 'EOF' | tee /usr/Adaptec_Event_Monitor/Email_Notification_Status.cfg || $Error
1
EOF
  cat << 'EOF' | tee /usr/Adaptec_Event_Monitor/Mail_Recipients.cfg || $Error
hwraid@softlayer.com,W
EOF
  cat << 'EOF' | tee /usr/Adaptec_Event_Monitor/SMTP_Server_Details.cfg || $Error
SMTP_SERVER=raidalerts-smtp.networklayer.com
SMTP_PORT=25
FROM_MAIL_ID=xxxxxx_yyyyyyyyyyyy@softlayer.com
USE_SECURE_MAIL_SERVER=no
EOF
#xxxxxx=user_id
#yyyyyyyyyyyy=something_id
fi

sed -i -e 's/^nrm.debugMask.*$/nrm.debugMask = 2/' /usr/Adaptec_Event_Monitor/NRMConfig.conf || $Error

yum -y install \
 nfs-utils \
 python-setuptools \
 screen \
 telnet \
 watchdog || $Error

yum -y --enablerepo=epel install \
 bash-completion || $Error

yum -y --disablerepo=\* --enablerepo=elrepo install drbd84-utils kmod-drbd84 || $Error

wget http://iij.dl.sourceforge.jp/linux-ha/61791/pacemaker-1.0.13-2.1.el6.x86_64.repo.tar.gz || $Error
tar xzvf pacemaker-1.0.13-2.1.el6.x86_64.repo.tar.gz -C /tmp/ || $Error
yum -y -c /tmp/pacemaker-1.0.13-2.1.el6.x86_64.repo/pacemaker.repo install pacemaker heartbeat pm_extras pm_diskd || $Error
rm -rf /tmp/pacemaker-1.0.13-2.1.el6.x86_64.repo pacemaker-1.0.13-2.1.el6.x86_64.repo.tar.gz || $Error

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

cat << 'EOF' | tee /etc/sysconfig/nfs || $Error
MOUNTD_NFS_V2="no"
RQUOTAD_PORT=875
#RPCRQUOTADOPTS=""
#LOCKDARG=
LOCKD_TCPPORT=32803
LOCKD_UDPPORT=32769
RPCNFSDARGS="-N 2"
#RPCNFSDCOUNT=8
#NFSD_MODULE="noload"
#NFSD_V4_GRACE=90
#RPCMOUNTDOPTS=""
MOUNTD_PORT=892
#STATDARG=""
STATD_PORT=662
STATD_OUTGOING_PORT=2020
RPCIDMAPDARGS=""
#SECURE_NFS="yes"
#RPCGSSDARGS=""
#RPCSVCGSSDARGS=""
#RDMA_PORT=20049
EOF
sed -i -e 's/^udp6/#udp6/' -e 's/^tcp6/#tcp6/' /etc/netconfig || $Error

sed -i -e 's/^#watchdog-device/watchdog-device/' /etc/watchdog.conf || $Error

sed -i -e 's/^IPMI_WATCHDOG=.*$/IPMI_WATCHDOG=yes/' /etc/sysconfig/ipmi || $Error
sed -i -e 's/^IPMI_WATCHDOG_OPTIONS=.*$/IPMI_WATCHDOG_OPTIONS="timeout=60 action=reset pretimeout=30 preaction=pre_int preop=preop_panic"/' /etc/sysconfig/ipmi || $Error
sed -i -e '/^blacklist iTCO_wdt$/d' /etc/modprobe.d/blacklist.conf || $Error
sed -i -e 's/^# watchdog drivers/# watchdog drivers\nblacklist iTCO_wdt/' /etc/modprobe.d/blacklist.conf || $Error

cat << 'EOF' | tee /etc/modprobe.d/softdog.conf || $Error
alias char-major-10-130 softdog
options softdog soft_margin=60
EOF
cat << 'EOF' | tee /etc/sysconfig/watchdog || $Error
VERBOSE=no
[ -d /proc/xen/ ] && modprobe softdog
EOF

easy_install softlayer || $Error

if [ ! -e /home/$MY_SL_ADMIN/.softlayer ]; then
  touch /home/$MY_SL_ADMIN/.softlayer || $Error
  chmod 600 /home/$MY_SL_ADMIN/.softlayer || $Error
  chown $MY_SL_ADMIN:$MY_SL_ADMIN /home/$MY_SL_ADMIN/.softlayer || $Error
  cat << 'EOF' | tee /home/$MY_SL_ADMIN/.softlayer || $Error
[softlayer]
username = SL999999
api_key = abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz01
endpoint_url = https://api.service.softlayer.com/xmlrpc/v3.1
timeout = 10
EOF
  touch /home/$MY_SL_ADMIN/.softlayer.user || $Error
  chmod 600 /home/$MY_SL_ADMIN/.softlayer.user || $Error
  chown $MY_SL_ADMIN:$MY_SL_ADMIN /home/$MY_SL_ADMIN/.softlayer.user || $Error
  echo 'user = SL999999:abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz01' | tee /home/$MY_SL_ADMIN/.softlayer.user || $Error
fi

cat << EOF | tee /etc/iscsi/initiatorname.iscsi || $Error
InitiatorName=iqn.1994-05.com.redhat:$(uname -n | awk -F. '{print $1}')
EOF

cat << 'EOF' | tee /etc/ha.d/param || $Error
HA1_NAME=backup11.example.com
HA2_NAME=backup12.example.com
HA1_IP=
HA2_IP=
HA_NAME=backup10.example.com
HA_VIP=
HA_GATEWAY_NAME=gateway1.example.com
HA1_HB_NAME=backup11-hb.example.com
HA2_HB_NAME=backup12-hb.example.com
HA1_HB_IP=192.168.0.2
HA2_HB_IP=192.168.0.3

NFS_CLIENTS=10.0.0.0/255.0.0.0

HA_NETWORK_123=$(echo $HA_VIP | awk -F. '{print $1 "." $2 "." $3}')
HA_NETWORK_4=$(($(echo $HA_VIP | awk -F. '{print $4}')&~63))
HA_GATEWAY="$HA_NETWORK_123.$((HA_NETWORK_4+1))"
[ -e /proc/net/bonding ] && NIC0=bond0 || NIC0=eth0
[ -e /proc/net/bonding ] && NIC1=bond1 || NIC1=eth1
[ "$(uname -n)" = "$HA1_NAME" ] && PRIV_IP=$HA1_IP || PRIV_IP=$HA2_IP
[ "$(uname -n)" = "$HA1_NAME" ] && PUB_IP=$HA1_HB_IP || PUB_IP=$HA2_HB_IP
[ "$(uname -n)" = "$HA1_NAME" ] && PEER_PRIV_IP=$HA2_IP || PEER_PRIV_IP=$HA1_IP
[ "$(uname -n)" = "$HA1_NAME" ] && PEER_PUB_IP=$HA2_HB_IP || PEER_PUB_IP=$HA1_HB_IP
HA_DEV1=xvdc
if [ ! -d /proc/xen/ ]; then
  lsmod | grep -q ^aacraid && HA_DEV1=sdc || HA_DEV1=sda
fi
EOF

if grep -q -v ^# /etc/cron.d/raid-check; then
  sed -i -e 's/^/#/' /etc/cron.d/raid-check || $Error
fi

for i in $(ls /etc/init.d/)
do
  chkconfig --del $i
  case $i in
    atd        ) chkconfig --add $i || $Error; chkconfig $i on  || $Error;;
    auditd     ) chkconfig --add $i || $Error; chkconfig $i on  || $Error;;
    crond      ) chkconfig --add $i || $Error; chkconfig $i on  || $Error;;
    iptables   ) chkconfig --add $i || $Error; chkconfig $i on  || $Error;;
    irqbalance ) chkconfig --add $i || $Error; chkconfig $i on  || $Error;;
    network    ) chkconfig --add $i || $Error; chkconfig $i on  || $Error;;
    psacct     ) chkconfig --add $i || $Error; chkconfig $i on  || $Error;;
    rsyslog    ) chkconfig --add $i || $Error; chkconfig $i on  || $Error;;
    sshd       ) chkconfig --add $i || $Error; chkconfig $i on  || $Error;;
    udev-post  ) chkconfig --add $i || $Error; chkconfig $i on  || $Error;;
    watchdog   ) chkconfig --add $i || $Error; chkconfig $i on  || $Error;;
    netfs      ) chkconfig --add $i || $Error; chkconfig $i off || $Error;;
    nfslock    ) chkconfig --add $i || $Error; chkconfig $i off || $Error;;
    rpcbind    ) chkconfig --add $i || $Error; chkconfig $i off || $Error;;
  esac
done
if [ -d /proc/xen/ ]; then
  chkconfig --add xe-linux-distribution || $Error
else
  chkconfig --add ntpd    || $Error; chkconfig ntpd    on || $Error
  chkconfig --add ipmi    || $Error; chkconfig ipmi    on || $Error
  chkconfig --add ipmievd || $Error; chkconfig ipmievd on || $Error
  if lsmod | grep -q ^aacraid; then
    chkconfig --add EventMonitorService || $Error
    chkconfig EventMonitorService on    || $Error
  fi
fi

mkdir -p /rescue || $Error

if grep ' /disk' /etc/fstab; then
  sed -i -e '/ \/disk/d' /etc/fstab || $Error
  umount /disk{,0} || :
  rmdir /disk* || $Error
  sed -i -e '/ swap  *swap /d' /etc/fstab || $Error
  swapoff /dev/sda3 || $Error
  if lsmod | grep -q ^aacraid; then
    fdisk /dev/sda << 'EOF' || :
u
d
5
d
4
d
3
d
2
n
p
3


n
p
2


d
3
p
w
EOF
    chmod 755 /rescue/once || $Error
    fdisk -H 64 -S 32 /dev/sdb << 'EOF' || :
o
n
p
1


t
82
p
w
EOF
    cat << 'EOF' | tee -a /etc/fstab || $Error
UUID=299ff4da-8897-405b-ae8e-5648a14fc81e swap  swap    pri=9,defaults  0 0
EOF
    cat << 'EOF' | tee /rescue/once || $Error
#!/bin/bash
resize2fs /dev/sda2
mkswap -L swap -U 299ff4da-8897-405b-ae8e-5648a14fc81e /dev/sdb1
swapon -a
rm -f /rescue/once
EOF
    if [ -e /dev/sdc -a ! -e /dev/sdc1 ]; then
      echo Yes | parted /dev/sdc mklabel msdos || $Error
      dd if=/dev/zero of=/dev/sdc bs=1M count=1 || $Error
      echo Yes | parted /dev/sdc mklabel gpt mkpart primary 1MiB 100% set 1 lvm on || $Error
      pvcreate /dev/sdc1 || $Error
      vgcreate -s 32M vg0 /dev/sdc1 || $Error
      for i in d e f g h i j k l m n o p q r s t u v w x y z
      do
        [ -e /dev/sd$i ] || break
        echo Yes | parted /dev/sd$i mklabel msdos || $Error
        dd if=/dev/zero of=/dev/sd$i bs=1M count=1 || $Error
        echo Yes | parted /dev/sd$i mklabel gpt mkpart primary 1MiB 100% set 1 lvm on || $Error
        vgextend vg0 /dev/sd${i}1 || $Error
      done
    fi
  else
    mkswap -L swap -U 299ff4da-8897-405b-ae8e-5648a14fc81e /dev/sda3 || $Error
    cat << 'EOF' | tee -a /etc/fstab || $Error
UUID=299ff4da-8897-405b-ae8e-5648a14fc81e swap  swap    pri=9,defaults  0 0
EOF
    fdisk /dev/sda << 'EOF' || :
t
5
fd
p
w
EOF
    pvcreate /dev/sda5 || $Error
    vgcreate -s 32M vg0 /dev/sda5 || $Error
    if [ -e /dev/sdb -a ! -e /dev/sdb1 ]; then
      for i in b c d e f g h i j k l m n o p q r s t u v w x y z
      do
        [ -e /dev/sd$i ] || break
        echo Yes | parted /dev/sd$i mklabel msdos || $Error
        dd if=/dev/zero of=/dev/sd$i bs=1M count=1 || $Error
        echo Yes | parted /dev/sd$i mklabel gpt mkpart primary 1MiB 100% set 1 lvm on || $Error
        vgextend vg0 /dev/sd${i}1 || $Error
      done
    fi
  fi
fi
if grep ^LABEL= /etc/fstab; then
  sed -i -e '/ swap  *swap /d' /etc/fstab || $Error
  swapoff /dev/xvdb1 || $Error
  fdisk -H 64 -S 32 /dev/xvdb << 'EOF' || :
o
n
p
1


t
82
p
w
EOF
  mkswap -L swap -U 299ff4da-8897-405b-ae8e-5648a14fc81e /dev/xvdb1 || $Error
  cat << 'EOF' | tee -a /etc/fstab || $Error
UUID=299ff4da-8897-405b-ae8e-5648a14fc81e swap  swap    pri=9,defaults  0 0
EOF
fi
if [ -e /dev/xvdc -a ! -e /dev/xvdc1 ]; then
  echo Yes | parted /dev/xvdc mklabel msdos || $Error
  dd if=/dev/zero of=/dev/xvdc bs=1M count=1 || $Error
  echo Yes | parted /dev/xvdc mklabel gpt mkpart primary 1MiB 100% set 1 lvm on || $Error
  pvcreate /dev/xvdc1 || $Error
  vgcreate -s 32M vg0 /dev/xvdc1 || $Error
  for i in d e f g h i j k l m n o p q r s t u v w x y z
  do
    [ -e /dev/xvd$i ] || break
    echo Yes | parted /dev/xvd$i mklabel msdos || $Error
    dd if=/dev/zero of=/dev/xvd$i bs=1M count=1 || $Error
    echo Yes | parted /dev/xvd$i mklabel gpt mkpart primary 1MiB 100% set 1 lvm on || $Error
    vgextend vg0 /dev/xvd${i}1 || $Error
  done
fi
blkid

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
sed -i -e "s/ip=[0-9.]* /ip=$1 /" /boot/grub/grub.conf
sed -i -e "s/gateway=[0-9.]* /gateway=$GATEWAY /" /boot/grub/grub.conf
[ "$2" = "norestart" ] || /etc/init.d/network restart
EOF
chmod 755 /rescue/mk_portable_ip || $Error

cat << 'EOF' | tee /rescue/mk_bond0 || $Error
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
chmod 755 /rescue/mk_bond0 || $Error

cat << 'EOF' | tee /rescue/mk_secure || $Error
#!/bin/sh
ifconfig bond1 down > /dev/null 2>&1
ifconfig eth1 down > /dev/null 2>&1
ifconfig eth3 down > /dev/null 2>&1
/etc/init.d/sshd stop > /dev/null 2>&1
kill -KILL $(ps -ef | grep [s]shd | grep anaconda | awk '{print $2}') > /dev/null 2>&1
EOF
chmod 755 /rescue/mk_secure || $Error

cat << 'EOF' | tee /rescue/mount || $Error
#!/bin/sh
mkdir -p /backup
[ "$1" ] && mount -t nfs $1:/backup /backup
[ -d /proc/xen/ ] && DEV=xvda || DEV=sda
mount -o rw,remount /dev/${DEV}2 /mnt/sysimage/
mount /dev/${DEV}1 /mnt/sysimage/boot
[ "$2" = "all" ] || exit 0
mount -t proc /proc /mnt/sysimage/proc
mount -t sysfs /sys /mnt/sysimage/sys
mount --bind /dev /mnt/sysimage/dev
EOF
chmod 755 /rescue/mount || $Error

cat << 'EOF' | tee /rescue/unmount || $Error
#!/bin/sh
umount /mnt/sysimage/dev
umount /mnt/sysimage/sys
umount /mnt/sysimage/proc
umount /mnt/sysimage/boot
[ -d /proc/xen/ ] && DEV=xvda || DEV=sda
mount -o ro,remount /dev/${DEV}2 /mnt/sysimage/
umount /backup
EOF
chmod 755 /rescue/unmount || $Error

cat << 'EOF' | tee /rescue/mk_offload_off || $Error
for i in eth0 eth1 eth2 eth3 bond0 bond1
do
  ifconfig $i > /dev/null 2>&1 || continue
  echo "[$i]"
  for j in rx tx sg tso ufo gso gro lro rxvlan txvlan ntuple rxhash
  do
    ethtool --offload $i $j off 2> /dev/null
  done
done
EOF
chmod 755 /rescue/mk_offload_off || $Error

cat << 'EOF' | tee /rescue/reboot || $Error
#!/bin/bash
if [ -d /proc/xen/ ]; then
  sed -i -e 's/^\(default=.*\)$/##rescue##\1\ndefault='"$(($(cat /boot/grub/grub.conf | grep -v ^# | tr '\n' ',' | sed -e 's/title/\ntitle/g' | grep ^title | awk '/ rescue / {print NR}')-1))/" /boot/grub/grub.conf && reboot
else
  kexec -l /boot/vmlinuz --initrd=/boot/initrd.img --command-line="rescue repo=http://mirrors.service.networklayer.com/centos/6.5/os/x86_64/ lang=en_US keymap=jp106 selinux=0 sshd=1 nomount ksdevice=eth0 ip=$(ifconfig $(ifconfig bond0 > /dev/null 2>&1 && echo bond0 || echo eth0) | grep inet | awk '{print $2}' | awk -F: '{print $2}') netmask=255.255.255.192 gateway=$(if route -n | grep -q '^10\.0\.0\.0'; then route -n | grep '^10\.0\.0\.0'; else route -n | grep '^0\.0\.0\.0'; fi | awk '{print $2}') dns=$(grep ^nameserver /etc/resolv.conf | head -1 | awk '{print $2}') mtu=9000 $@" && reboot
fi
EOF
chmod 755 /rescue/reboot || $Error

cat << 'EOF' | tee /usr/local/sbin/reboot_quick || $Error
#!/bin/bash
[ "$1" = "noreboot" ] && shift && NOREBOOT=yes
if [ ! -d /proc/xen/ ]; then
  LINE=$(grep ^default= /boot/grub/grub.conf | sed 's/default=//')
  KVER=$(grep -v ^# /boot/grub/grub.conf | grep vmlinuz- | sed 's/^.*vmlinuz-\([^ ]*\) .*$/\1/' | head -$((LINE+1)) | tail -1)
  CMDLINE="$(grep -v ^# /boot/grub/grub.conf | grep vmlinuz- | sed 's/^.*vmlinuz-\([^ ]* \)\(.*\)$/\2/' | head -$((LINE+1)) | tail -1) $@"
  /sbin/kexec -l /boot/vmlinuz-$KVER --initrd=/boot/initramfs-$KVER.img --command-line="$CMDLINE"
fi
[ "$NOREBOOT" = "yes" ] || /sbin/reboot
EOF
chmod 755 /usr/local/sbin/reboot_quick || $Error

if [ "$MY_ROOT_PW" ]; then
  echo $MY_ROOT_PW | passwd --stdin root || $Error
else
  dd if=/dev/urandom bs=1 count=50 2> /dev/null | base64 | passwd --stdin root || $Error
fi

/usr/local/sbin/reboot_quick || $Error
