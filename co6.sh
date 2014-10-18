#!/bin/bash

#https://raw.githubusercontent.com/pcserver-jp/SoftLayer/master/co6.sh

MY_ROOT_PW=$(dd if=/dev/urandom bs=1 count=48 2> /dev/null | base64)
MY_SL_ADMIN=sl-admin
MY_SL_ADMIN_INIT_PW=sl-admin
MY_SL_ADMIN_ID=65501
WHEEL_SUDO_NOPASSWD=yes
MY_NTOP_PW=$(dd if=/dev/urandom bs=1 count=6 2> /dev/null | base64)
CENTOS_VER=6.5

#DEV_COLOR="1;42m"
#STG_COLOR="5;43m"
#PRD_COLOR="1;41m"
MY_COLOR="1;41m"

SL_ACCOUNT=SL999999
SL_API_KEY=abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz01

MAIL_USER=softlayer@example.com
MAIL_PW=password
MAIL_HELLO=example.com
MAIL_FROM=softlayer@example.com

mkdir -p /etc/ha.d/
cat << EOF | tee /etc/ha.d/param_cluster > /dev/null
HA1_IP=
HA2_IP=
HA_VIP=
HA_DOMAIN=example.com
HA1_NODE=backup11
HA2_NODE=backup12
HA_NODE=backup1
HA_GATEWAY_NODE=gateway1
SSH_CLIENTS=10.0.0.0/8
DRBD_SIZE=90G
DRBD_PASSWORD=password
VIP_CLIENTS=10.0.0.0/8
EOF

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

if [ "$(id)" != "$(id root)" ]; then
  $Error : no root user
  exit 1
fi

if ! grep -q ^ssh- /root/.ssh/authorized_keys; then
  $Error : no sshkey
  exit 1
fi

if [ ! -e /root/post_install.sh -a $(ls /root/post_install.* | wc -l) -eq 1 ];then
  if [ -x /root/post_install.* ]; then
    mv /root/post_install.* /root/post_install.sh 2> /dev/null || $Error
  fi
fi
exec >> /root/post_install.log || $Error
exec 2>&1 || $Error
set -x || $Error
chmod 600 /root/post_install.log || $Error

mkdir -p /root/.pw || $Error
chmod 700 /root/.pw || $Error
echo -n $MY_ROOT_PW | tee /root/.pw/root > /dev/null || $Error
chmod 400 /root/.pw/root || $Error
echo -n $MY_NTOP_PW | tee /root/.pw/ntop > /dev/null || $Error
chmod 400 /root/.pw/ntop || $Error

#http://knowledgelayer.softlayer.com/faq/what-ip-ranges-do-i-allow-through-firewall
if [ -d /proc/xen/ ]; then
  MY_DC=$(curl -k https://api.service.softlayer.com/rest/v3/SoftLayer_Resource_Metadata/getDatacenter 2> /dev/null |
    sed -n -e 's/^"\(.*\)"$/\1/p')
else
  MY_DC=$(grep ^ssh- /root/.ssh/authorized_keys | head -1 |
    sed -n -e 's/^ssh-[^ ]* [^ ]* \(.*@\([a-z0-9]*\)\)$/\2/p')
fi
case "$MY_DC" in
  "ams01" ) :;;
  "dal01" ) :;;
  "dal05" ) :;;
  "dal06" ) :;;
  "dal07" ) :;;
  "hkg02" ) :;;
  "hou02" ) :;;
  "lon01" ) MY_DC=lon02;;
  "lon02" ) :;;
  "mel01" ) :;;
  "sea01" ) :;;
  "sjc01" ) :;;
  "sng01" ) :;;
  "tor01" ) :;;
  "wdc01" ) :;;
  * ) MY_DC=hkg02;;
esac || $Error
mkdir -p /rescue || $Error
echo $MY_DC | tee /rescue/datacenter || $Error

iptables -nvL || $Error
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
-A INPUT -p tcp  --dport 22   -m tcp -m state --state NEW -s 10.0.0.0/8 -j ACCEPT
-A INPUT -p tcp  --dport 3001 -m tcp -m state --state NEW -s 10.0.0.0/8 -j ACCEPT
-A INPUT -p tcp  --dport 3003 -m tcp -m state --state NEW -s 10.0.0.0/8 -j ACCEPT
-A INPUT -p icmp                                          -s 10.0.0.0/8 -j ACCEPT
#-A INPUT -j LOG --log-prefix "ip_tables: " --log-level=debug
-A INPUT -j REJECT --reject-with icmp-host-prohibited
########## FORWARD ##########
-A FORWARD -j REJECT --reject-with icmp-host-prohibited
COMMIT
EOF
if ! ifconfig bond0 > /dev/null 2>&1; then
  sed -i -e '/bond0/ s/^/#/' /etc/sysconfig/iptables || $Error
  sed -i -e '/bond1/ s/^/#/' /etc/sysconfig/iptables || $Error
  sed -i -e '/eth2/  s/^/#/' /etc/sysconfig/iptables || $Error
  sed -i -e '/eth3/  s/^/#/' /etc/sysconfig/iptables || $Error
fi
case $MY_DC in
  "ams01" ) sed -i -e 's/119\.81\.138/159.253.158/' /etc/sysconfig/iptables || $Error;;
  "dal01" ) sed -i -e 's/119\.81\.138/66.228.118/'  /etc/sysconfig/iptables || $Error;;
  "dal05" ) sed -i -e 's/119\.81\.138/173.192.118/' /etc/sysconfig/iptables || $Error;;
  "dal06" ) sed -i -e 's/119\.81\.138/184.172.118/' /etc/sysconfig/iptables || $Error;;
  "dal07" ) sed -i -e 's/119\.81\.138/50.22.118/'   /etc/sysconfig/iptables || $Error;;
# "hkg02" ) sed -i -e 's/119\.81\.138/119.81.138/'  /etc/sysconfig/iptables || $Error;;
  "hou02" ) sed -i -e 's/119\.81\.138/173.193.118/' /etc/sysconfig/iptables || $Error;;
  "lon02" ) sed -i -e 's/119\.81\.138/5.10.118/'    /etc/sysconfig/iptables || $Error;;
  "mel01" ) sed -i -e 's/119\.81\.138/168.1.118/'   /etc/sysconfig/iptables || $Error;;
  "sea01" ) sed -i -e 's/119\.81\.138/67.228.118/'  /etc/sysconfig/iptables || $Error;;
  "sjc01" ) sed -i -e 's/119\.81\.138/50.23.118/'   /etc/sysconfig/iptables || $Error;;
  "sng01" ) sed -i -e 's/119\.81\.138/174.133.118/' /etc/sysconfig/iptables || $Error;;
  "tor01" ) sed -i -e 's/119\.81\.138/158.85.118/'  /etc/sysconfig/iptables || $Error;;
  "wdc01" ) sed -i -e 's/119\.81\.138/208.43.118/'  /etc/sysconfig/iptables || $Error;;
esac
/etc/init.d/iptables restart || $Error
iptables -nvL || $Error
iptables -t nat -nvL || $Error
iptables -t mangle -nvL || $Error

cat /etc/login.defs || $Error
cat /etc/sysconfig/authconfig || $Error
cat /etc/pam.d/password-auth || $Error
cat /etc/pam.d/password-auth-ac || $Error
cat /etc/pam.d/system-auth || $Error
cat /etc/pam.d/system-auth-ac || $Error
#authconfig --passalgo=sha512 --update || $Error
#sed -i -e 's/^ENCRYPT_METHOD .*$/ENCRYPT_METHOD  SHA512/' /etc/login.defs || $Error
#sed -i -e '/^MD5_CRYPT_ENAB/d' /etc/login.defs || $Error
sed -i -e 's/^PASSWDALGORITHM=.*$/PASSWDALGORITHM=sha512/' /etc/sysconfig/authconfig || $Error
sed -i -e 's/md5/sha512/' /etc/pam.d/password-auth || $Error
sed -i -e 's/md5/sha512/' /etc/pam.d/password-auth-ac || $Error
sed -i -e 's/md5/sha512/' /etc/pam.d/system-auth || $Error
sed -i -e 's/md5/sha512/' /etc/pam.d/system-auth-ac || $Error

cat << 'EOF' | tee /etc/login.defs || $Error
MAIL_DIR        /var/spool/mail
PASS_MAX_DAYS   99999
PASS_MIN_DAYS   0
PASS_MIN_LEN    5
PASS_WARN_AGE   7
UID_MIN         500
UID_MAX         60000
GID_MIN         500
GID_MAX         60000
CREATE_HOME     yes
UMASK           077
USERGROUPS_ENAB yes
ENCRYPT_METHOD  SHA512
SU_WHEEL_ONLY   yes
EOF

cat /etc/pam.d/su || $Error
sed -i -e '/pam_wheel.so use_uid/ s/^#//' /etc/pam.d/su || $Error

touch /etc/sudoers.d/wheel || $Error
chmod 640 /etc/sudoers.d/wheel || $Error
if [ "$WHEEL_SUDO_NOPASSWD" = "yes" ]; then
  echo '%wheel ALL=(ALL) NOPASSWD: ALL' | tee /etc/sudoers.d/wheel || $Error
else
  echo '%wheel ALL=(ALL) ALL'           | tee /etc/sudoers.d/wheel || $Error
fi

cat /etc/default/useradd || $Error
sed -i -e 's/^CREATE_MAIL_SPOOL=.*$/CREATE_MAIL_SPOOL=no/' /etc/default/useradd || $Error

cat << 'EOF' | tee /usr/local/bin/logger_ex || $Error
#!/usr/bin/perl
my $ident = $ARGV[0];
my $facility = $ARGV[1];
my $level = $ARGV[2];
use Sys::Syslog qw( :DEFAULT setlogsock );
setlogsock('unix');
openlog($ident, 'pid', $facility);
while ($log = <STDIN>) {
  syslog($level, $log);
}
closelog
EOF
chmod 755 /usr/local/bin/logger_ex || $Error

cat << 'EOF' | tee /usr/local/bin/operation_logger || $Error
#!/bin/bash
export PROMPT_COMMAND='printf "\033]0;%s@%s:%s\007" "${USER}" "${HOSTNAME}" "${PWD/#$HOME/~}";alias l.="ls -d .* --color=auto";alias ll="ls -l --color=auto";alias ls="ls --color=auto";alias vi="vim";alias which="alias | /usr/bin/which --tty-only --read-alias --show-dot --show-tilde";alias dstat="dstat -Tclmdrn";[ "$PS1" ] && PS1='\''[\u@\[\e[1;41m\]\H\[\e[0m\] \t \w] \n\$ '\'';PROMPT_COMMAND='\''printf "\033]0;%s@%s:%s\007" "${USER}" "${HOSTNAME}" "${PWD/#$HOME/~}"'\'
/usr/bin/mkfifo -m 0600 /dev/shm/$USER.$$
(/bin/sed -u -e 's/[^[:graph:]]/ /g' /dev/shm/$USER.$$ | /usr/local/bin/logger_ex $USER.$$ local0 info; /bin/rm -f /dev/shm/$USER.$$) &
exec /usr/bin/script -fq /dev/shm/$USER.$$
EOF
chmod 755 /usr/local/bin/operation_logger || $Error

if ! id $MY_SL_ADMIN; then
  sed -i -e 's%^saslauth:.*$%saslauth:x:76:76:"Saslauthd user":/var/empty/saslauth:/sbin/nologin%' /etc/passwd || $Error
  groupadd -g 65401 haclient || $Error
  useradd -u 65401 -g haclient -c "cluster user" -d /var/lib/heartbeat/cores/hacluster -s /sbin/nologin -r hacluster || $Error
  groupadd -g 65402 munin || $Error
  useradd -u 65402 -g munin -c "Munin user" -d /var/lib/munin -s /sbin/nologin -r munin || $Error
  groupadd -g 65403 vnstat || $Error
  useradd -u 65403 -g vnstat -c "vnStat user" -d /var/lib/vnstat -s /sbin/nologin -r vnstat || $Error
  groupadd -g 65404 openvpn || $Error
  useradd -u 65404 -g openvpn -c OpenVPN -d /etc/openvpn -s /sbin/nologin -r openvpn || $Error
  groupadd -g 65405 clam || $Error
  useradd -u 65405 -g clam -c "Clam Anti Virus Checker" -d /var/lib/clamav -s /sbin/nologin -r clam || $Error
  groupadd -g 65406 clam-update || $Error
  useradd -u 65406 -g clam-update -c "clamav-unofficial-sigs user account" -d /var/lib/clamav-unofficial-sigs -r clam-update || $Error
  #groupadd -g 65407 clamsmtp || $Error
  useradd -u 65407 -g mail -c "User to own clamsmtp directories and default processes" -d /var/lib/clamd.clamsmtp -s /sbin/nologin -r clamsmtp || $Error
  groupadd -g 65408 memcached || $Error
  useradd -u 65408 -g memcached -c "Memcached daemon" -d /var/run/memcached -s /sbin/nologin -r memcached || $Error
  groupadd -g 65409 redis || $Error
  useradd -u 65409 -g redis -c "Redis Server" -d /var/lib/redis -s /sbin/nologin -r redis || $Error
  groupadd -g 65410 logcheck || $Error
  useradd -u 65410 -g logcheck -c "Logcheck user" -d /var/lib/logcheck -s /sbin/nologin -r logcheck || $Error
  groupadd -g 65411 ntop || $Error
  useradd -u 65411 -g ntop -c ntop -d /var/lib/ntop -s /sbin/nologin -r ntop || $Error
  groupadd -g 65412 cgred || $Error
  groupadd -g 65413 ecryptfs || $Error
  groupadd -g 65414 rsshusers || $Error

  groupadd -g $MY_SL_ADMIN_ID $MY_SL_ADMIN || $Error
  useradd -g $MY_SL_ADMIN -G wheel,munin -u $MY_SL_ADMIN_ID $MY_SL_ADMIN || $Error
  echo $MY_SL_ADMIN_INIT_PW | passwd --stdin $MY_SL_ADMIN || $Error
  chage -d 0 $MY_SL_ADMIN || $Error
  cp -a /root/.ssh /home/$MY_SL_ADMIN/ || $Error
  chown -R $MY_SL_ADMIN:$MY_SL_ADMIN /home/$MY_SL_ADMIN/.ssh || $Error
  cat << 'EOF' | tee -a /home/$MY_SL_ADMIN/.bash_profile || $Error
[ "$PS1" ] && exec /usr/local/bin/operation_logger
EOF
  cat << 'EOF' | tee -a /etc/skel/.bash_profile || $Error
[ "$PS1" ] && exec /usr/local/bin/operation_logger
EOF
  cat << 'EOF' | tee -a /root/.bash_profile || $Error
[ "$PS1" ] && exec /usr/local/bin/operation_logger
EOF
  if [ MY_COLOR != "1;41m" ]; then
    sed -i -e "s/1;41m/$MY_COLOR/" /usr/local/bin/operation_logger || $Error
  fi
fi

ifconfig || $Error
route -n || $Error
netstat -anp || $Error
: --------------------------------------------------------------------------------
for i in eth0 eth1 eth2 eth3 bond0 bond1
do
  ifconfig $i > /dev/null 2>&1 || break
#  for j in "" --show-pause --show-coalesce --show-ring --driver --register-dump --eeprom-dump --show-features --show-permaddr --statistics --show-nfc --get-dump --show-time-stamping --show-rxfh-indir --show-channels --dump-module-eeprom --show-priv-flags --show-eee
  for j in "" --show-features
  do
    : --------------------------------------------------------------------------------
    ethtool $j $i 2> /dev/null || $Error
  done
done
: --------------------------------------------------------------------------------
[ -e /proc/net/bonding/bond0 ] && cat /proc/net/bonding/bond0
: --------------------------------------------------------------------------------
[ -e /proc/net/bonding/bond1 ] && cat /proc/net/bonding/bond1
: --------------------------------------------------------------------------------
cat /etc/resolv.conf || $Error
cat /etc/nsswitch.conf || $Error
ifconfig bond0 > /dev/null 2>&1 && NIC0=bond0 || NIC0=eth0
ifconfig bond1 > /dev/null 2>&1 && NIC1=bond1 || NIC1=eth1
IP0=$(ifconfig $NIC0 | grep ' inet ' | awk '{print $2}' | awk -F: '{print $2}')
IP1=$(ifconfig $NIC1 | grep ' inet ' | awk '{print $2}' | awk -F: '{print $2}')
NETMASK0=255.255.255.192
NETMASK1=255.255.255.248
GATEWAY0=$(if route -n | grep -q '^10\.0\.0\.0'; then route -n | grep '^10\.0\.0\.0'; else route -n | grep '^0\.0\.0\.0'; fi | awk '{print $2}')
GATEWAY1=$(route -n | grep '^0\.0\.0\.0' | awk '{print $2}')
DNS0=10.0.80.11
if [ ! -e /rescue/private_primary_ip ]; then
  echo $IP0 | tee /rescue/private_primary_ip || $Error
fi
if [ ! -e /rescue/public_primary_ip ]; then
  echo $IP1 | tee /rescue/public_primary_ip || $Error
fi
if [ ! -e /rescue/private_primary_netmask ]; then
  echo $NETMASK0 | tee /rescue/private_primary_netmask || $Error
fi
if [ ! -e /rescue/public_primary_netmask ]; then
  echo $NETMASK1 | tee /rescue/public_primary_netmask || $Error
fi
if [ ! -e /rescue/private_primary_gateway ]; then
  echo $GATEWAY0 | tee /rescue/private_primary_gateway || $Error
fi
if [ ! -e /rescue/public_primary_gateway ]; then
  echo $GATEWAY1 | tee /rescue/public_primary_gateway || $Error
fi
cat /etc/sysconfig/network-scripts/ifcfg-lo
for i in eth0 eth1 eth2 eth3 bond0 bond1
do
  if [ -e /etc/sysconfig/network-scripts/ifcfg-$i  ]; then
    cat /etc/sysconfig/network-scripts/ifcfg-$i || $Error
    sed -i -e '/^NM_CONTROLLED.*$/d' /etc/sysconfig/network-scripts/ifcfg-$i || $Error
    echo 'NM_CONTROLLED=no' | tee -a /etc/sysconfig/network-scripts/ifcfg-$i || $Error
  fi
done
sed -i -e '/^MTU=/d' /etc/sysconfig/network-scripts/ifcfg-$NIC0 || $Error
if [ ! -d /proc/xen/ ]; then
  echo "MTU=9000" | tee -a /etc/sysconfig/network-scripts/ifcfg-$NIC0 || $Error
fi

cat << EOF | tee /etc/resolv.conf || $Error
nameserver 10.0.80.11
nameserver 10.0.80.12
options single-request
EOF

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
if ! grep -q '^/rescue/mk_offload_off$' /etc/rc.d/rc.local; then
  echo '/rescue/mk_offload_off' | tee -a /etc/rc.d/rc.local || $Error
  echo '[ -x /rescue/once ] && /rescue/once' | tee -a /etc/rc.d/rc.local || $Error
fi

cat /etc/sysctl.conf || $Error
sed -i -e 's/^net\.bridge/#net.bridge/' /etc/sysctl.conf || $Error

if ! grep -q '^NOZEROCONF' /etc/sysconfig/network; then
  cat /etc/sysconfig/network || $Error
  cat << 'EOF' | tee -a /etc/sysconfig/network || $Error
NOZEROCONF=yes
NETWORKING_IPV6=no
IPV6INIT=no
IPV6_ROUTER=no
IPV6_AUTOCONF=no
IPV6FORWARDING=no
IPV6TO4INIT=no
IPV6_CONTROL_RADVD=no
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

if [ -e /etc/modprobe.conf ]; then
  cat /etc/modprobe.conf || $Error
  mv /etc/modprobe.conf /etc/modprobe.d/bonding.conf || $Error
fi

cat << 'EOF' | tee /etc/modprobe.d/ixgbe.conf || $Error
options ixgbe IntMode=1,1
EOF

cat << 'EOF' | tee /etc/modprobe.d/anaconda.conf || $Error
options floppy allowed_drive_mask=0
EOF

rm -rf /etc/multipath/ || $Error

lsblk || $Error
blkid || $Error
df -h || $Error
free || $Error
cat /etc/fstab || $Error
mount || $Error
cat /proc/mounts || $Error
swapon -s || $Error
fdisk -l || $Error
parted -l || $Error
lsmod | sort || $Error
dmidecode || $Error
cat /proc/cpuinfo || $Error
cat /proc/meminfo || $Error
cat /proc/cmdline || $Error
uname -a || $Error
w || $Error
sysctl -a || $Error
sysctl -p || $Error
ps -ef || $Error
chkconfig --list || $Error
if grep ' /disk' /etc/fstab; then
  sed -i -e '/ \/disk/d' /etc/fstab || $Error
  umount /disk* || :
  while umount /disk1; do :; done
  rmdir /disk* || :
  sed -i -e '/ swap  *swap /d' /etc/fstab || $Error
  swapoff /dev/sda3 || $Error
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
  pushd / || $Error
  tar czvf /boot.tgz boot || $Error
  umount /boot || $Error
  mkfs.ext4 -L boot -U 7e70ca17-3016-4b92-8542-615d909115f9 /dev/sda1 || $Error
  tune2fs -c 0 -i 0 /dev/sda1 || $Error
  sed -i -e '/ \/boot /d' /etc/fstab || $Error
  echo 'UUID=7e70ca17-3016-4b92-8542-615d909115f9 /boot ext4    defaults        1 2' | tee -a /etc/fstab || $Error
  mount -a || $Error
  tar xzvf /boot.tgz || $Error
  rm -f /boot.tgz || $Error
  grub-install /dev/sda || $Error
  if lsmod | grep -q ^aacraid; then
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
    cat << 'EOF' | tee /rescue/once || $Error
#!/bin/bash
exec >> /root/post_install.log
exec 2>&1
set -x
resize2fs /dev/sda2
mkswap -L swap -U 299ff4da-8897-405b-ae8e-5648a14fc81e /dev/sdb1
cat << 'EOF_FSTAB' | tee -a /etc/fstab
UUID=299ff4da-8897-405b-ae8e-5648a14fc81e swap  swap    pri=9,defaults  0 0
EOF_FSTAB
swapon -a
if [ -e /dev/sdc ]; then
  chkconfig --add lvm2-monitor
  /etc/init.d/lvm2-monitor start
  echo Yes | parted /dev/sdc mklabel msdos
  echo Yes | parted /dev/sdc mklabel gpt
  echo Yes | parted /dev/sdc mkpart primary 1MiB 100% set 1 lvm on
  pvcreate /dev/sdc1
  vgcreate -s 32M vg0 /dev/sdc1
  for i in d e f g h i j k l m n o p q r s t u v w x y z
  do
    [ -e /dev/sd$i ] || break
    echo Yes | parted /dev/sd$i mklabel msdos
    echo Yes | parted /dev/sd$i mklabel gpt
    echo Yes | parted /dev/sd$i mkpart primary 1MiB 100% set 1 lvm on
    pvcreate /dev/sd${i}1
    vgextend vg0 /dev/sd${i}1
  done
fi
rm -f /rescue/once
EOF
    chmod 755 /rescue/once || $Error
    if [ -e /dev/sdc ]; then
      echo Yes | parted /dev/sdc mklabel msdos || :
      dd if=/dev/zero of=/dev/sdc bs=1M count=10 || $Error
      for i in d e f g h i j k l m n o p q r s t u v w x y z
      do
        [ -e /dev/sd$i ] || break
        echo Yes | parted /dev/sd$i mklabel msdos || :
        dd if=/dev/zero of=/dev/sd$i bs=1M count=10 || $Error
      done
    fi
  else
    cat << 'EOF' | tee /rescue/once || $Error
#!/bin/bash
exec >> /root/post_install.log
exec 2>&1
set -x
resize2fs /dev/sda2
dd if=/dev/zero of=/.swap bs=1M count=2048
mkswap -f -L swap -U 299ff4da-8897-405b-ae8e-5648a14fc81e /.swap
cat << 'EOF_FSTAB' | tee -a /etc/fstab
/.swap                                    swap  swap    pri=0,defaults  0 0
EOF_FSTAB
swapon -a
if [ -e /dev/sdb ]; then
  chkconfig --add lvm2-monitor
  /etc/init.d/lvm2-monitor start
  echo Yes | parted /dev/sdb mklabel msdos
  echo Yes | parted /dev/sdb mklabel gpt
  echo Yes | parted /dev/sdb mkpart primary 1MiB 100% set 1 lvm on
  pvcreate /dev/sdb1
  vgcreate -s 32M vg0 /dev/sdb1
  for i in c d e f g h i j k l m n o p q r s t u v w x y z
  do
    [ -e /dev/sd$i ] || break
    echo Yes | parted /dev/sd$i mklabel msdos
    echo Yes | parted /dev/sd$i mklabel gpt
    echo Yes | parted /dev/sd$i mkpart primary 1MiB 100% set 1 lvm on
    pvcreate /dev/sd${i}1
    vgextend vg0 /dev/sd${i}1
  done
fi
rm -f /rescue/once
EOF
    chmod 755 /rescue/once || $Error
    if [ -e /dev/sdb ]; then
      echo Yes | parted /dev/sdb mklabel msdos || :
      dd if=/dev/zero of=/dev/sdb bs=1M count=10 || $Error
      for i in c d e f g h i j k l m n o p q r s t u v w x y z
      do
        [ -e /dev/sd$i ] || break
        echo Yes | parted /dev/sd$i mklabel msdos || :
        dd if=/dev/zero of=/dev/sd$i bs=1M count=10 || $Error
      done
    fi
  fi
fi
if grep ^LABEL= /etc/fstab; then
  pushd / || $Error
  tar czvf /boot.tgz boot || $Error
  umount /boot || $Error
  mkfs.ext4 -L boot -U 7e70ca17-3016-4b92-8542-615d909115f9 /dev/xvda1 || $Error
  tune2fs -c 0 -i 0 /dev/xvda1 || $Error
  sed -i -e '/ \/boot /d' /etc/fstab || $Error
  echo 'UUID=7e70ca17-3016-4b92-8542-615d909115f9 /boot ext4    defaults        1 2' | tee -a /etc/fstab || $Error
  mount -a || $Error
  tar xzvf /boot.tgz || $Error
  rm -f /boot.tgz || $Error
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
  cat << 'EOF' | tee /rescue/once || $Error
#!/bin/bash
exec >> /root/post_install.log
exec 2>&1
set -x
mkswap -L swap -U 299ff4da-8897-405b-ae8e-5648a14fc81e /dev/xvdb1
cat << 'EOF_FSTAB' | tee -a /etc/fstab
UUID=299ff4da-8897-405b-ae8e-5648a14fc81e swap  swap    pri=9,defaults  0 0
EOF_FSTAB
swapon -a
if [ -e /dev/xvdc ]; then
  chkconfig --add lvm2-monitor
  /etc/init.d/lvm2-monitor start
  echo Yes | parted /dev/xvdc mklabel msdos
  echo Yes | parted /dev/xvdc mklabel gpt
  echo Yes | parted /dev/xvdc mkpart primary 1MiB 100% set 1 lvm on
  pvcreate /dev/xvdc1
  vgcreate -s 32M vg0 /dev/xvdc1
  for i in d e f
  do
    [ -e /dev/xvd$i ] || break
    echo Yes | parted /dev/xvd$i mklabel msdos
    echo Yes | parted /dev/xvd$i mklabel gpt
    echo Yes | parted /dev/xvd$i mkpart primary 1MiB 100% set 1 lvm on
    pvcreate /dev/xvd${i}1
    vgextend vg0 /dev/xvd${i}1
  done
fi
rm -f /rescue/once
EOF
  chmod 755 /rescue/once || $Error
fi
if [ -e /dev/xvdc ]; then
  echo Yes | parted /dev/xvdc mklabel msdos || :
  dd if=/dev/zero of=/dev/xvdc bs=1M count=10 || $Error
  for i in d e f
  do
    [ -e /dev/xvd$i ] || break
    echo Yes | parted /dev/xvd$i mklabel msdos || :
    dd if=/dev/zero of=/dev/xvd$i bs=1M count=10 || $Error
  done
fi
blkid

cat /etc/inittab || $Error
echo 'id:3:initdefault:' | tee /etc/inittab || $Error

cat /boot/grub/grub.conf || $Error
if ! grep -q ' selinux=0 ' /boot/grub/grub.conf; then
  wget -q -O /boot/vmlinuz http://mirrors.service.networklayer.com/centos/$CENTOS_VER/os/x86_64/isolinux/vmlinuz || $Error
  wget -q -O /boot/initrd.img http://mirrors.service.networklayer.com/centos/$CENTOS_VER/os/x86_64/isolinux/initrd.img || $Error
  sed -i -e 's/^default=0/default=0\nfallback=1/' /boot/grub/grub.conf || $Error
  sed -i -e 's/^timeout=.*$/timeout=3/' /boot/grub/grub.conf || $Error
  sed -i -e 's/^hiddenmenu/#hiddenmenu/' /boot/grub/grub.conf || $Error
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
  sed -i -e '/^[^#]/ s/  / /g' /boot/grub/grub.conf || $Error
  sed -i -e 's/biosdevname=0/biosdevname=0 selinux=0 crashkernel=auto KEYBOARDTYPE=pc KEYTABLE=106 LANG=en_US.UTF-8 SYSFONT=latarcyrheb-sun16 rd_NO_LUKS rd_NO_LVM rd_NO_MD rd_NO_DM elevator=deadline/g' /boot/grub/grub.conf || $Error
#  if [ ! -d /proc/xen/ ]; then
#    sed -i -e 's/ biosdevname=0/ biosdevname=0 console=tty0 console=ttyS1,19200n8r/g' /boot/grub/grub.conf || $Error
#    sed -i -e 's%^#hiddenmenu%#hiddenmenu\nserial --unit=1 --speed=19200 --word=8 --parity=no --stop=1\nterminal --timeout=5 serial console%' /boot/grub/grub.conf || $Error
#  fi
  if ! grep -q ' rescue ' /boot/grub/grub.conf; then
    cat << EOF | tee -a /boot/grub/grub.conf || $Error
title Rescue
^root (hd0,0)
^kernel /vmlinuz rescue repo=http://mirrors.service.networklayer.com/centos/$CENTOS_VER/os/x86_64/ lang=en_US keymap=jp106 selinux=0 biosdevname=0 nomount sshd=1 ksdevice=eth0 ip=$IP0 netmask=255.255.255.192 gateway=$GATEWAY0 dns=$DNS0
^initrd /initrd.img
EOF
    sed -i -e 's/^^/\t/g' /boot/grub/grub.conf || $Error
    if [ -d /proc/xen/ ]; then
      sed -i -e 's/ nomount/ console=hvc0 nomount/g' /boot/grub/grub.conf || $Error
    else
      sed -i -e 's/ nomount/ nomodeset pcie_aspm=off nomount/g' /boot/grub/grub.conf || $Error
    fi
  fi
  cat /boot/grub/grub.conf || $Error
  cat /etc/sysconfig/grub || $Error
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
fi

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
ln -s /usr/local/sbin/reboot_quick /rescue/reboot_quick || $Error

cat << 'EOF' | tee /rescue/reboot || $Error
#!/bin/bash
if [ -d /proc/xen/ ]; then
  sed -i -e 's/^\(default=.*\)$/##rescue##\1\ndefault='"$(($(cat /boot/grub/grub.conf | grep -v ^# | tr '\n' ',' | sed -e 's/title/\ntitle/g' | grep ^title | awk '/ rescue / {print NR}')-1))/" /boot/grub/grub.conf && reboot
else
  kexec -l /boot/vmlinuz --initrd=/boot/initrd.img --command-line="rescue repo=http://mirrors.service.networklayer.com/centos/6.5/os/x86_64/ lang=en_US keymap=jp106 selinux=0 sshd=1 nomount ksdevice=eth0 ip=$(ifconfig $(ifconfig bond0 > /dev/null 2>&1 && echo bond0 || echo eth0) | grep inet | awk '{print $2}' | awk -F: '{print $2}') netmask=255.255.255.192 gateway=$(if route -n | grep -q '^10\.0\.0\.0'; then route -n | grep '^10\.0\.0\.0'; else route -n | grep '^0\.0\.0\.0'; fi | awk '{print $2}') dns=$(grep ^nameserver /etc/resolv.conf | head -1 | awk '{print $2}') mtu=9000 biosdevname=0 nomodeset pcie_aspm=off $@" && reboot
fi
EOF
chmod 755 /rescue/reboot || $Error

cat << 'EOF' | tee /rescue/backup || $Error
#!/bin/bash
if [ "$1" = "" ]; then
  echo Usage: $0  nfsserver_ip_address
  exit 1
fi
echo "rpcinfo $1"
if ! rpcinfo $1; then
  echo "Invalid Parameter: $1"
  exit 1
fi
if [ -d /proc/xen/ ]; then
  sed -i -e 's/^\(default=.*\)$/##rescue##\1\ndefault='"$(($(grep ^title /boot/grub/grub.conf | wc -l)-1))/" -e '/vmlinuz / s%^.*$%\tkernel /vmlinuz lang=en_US keymap=jp106 selinux=0 ksdevice=eth0 ip='"$(ifconfig eth0 | grep inet | awk '{print $2}' | awk -F: '{print $2}') netmask=255.255.255.192 gateway=$(if route -n | grep -q '^10\.0\.0\.0'; then route -n | grep '^10\.0\.0\.0'; else route -n | grep '^0\.0\.0\.0'; fi | awk '{print $2}') dns=$(grep ^nameserver /etc/resolv.conf | head -1 | awk '{print $2}') ks=nfs:$1:/backup/ks/backup_boot_root.cfg%" /boot/grub/grub.conf && reboot
else
  kexec -l /boot/vmlinuz --initrd=/boot/initrd.img --command-line="lang=en_US keymap=jp106 selinux=0 ksdevice=eth0 ip=$(ifconfig $(ifconfig bond0 > /dev/null 2>&1 && echo bond0 || echo eth0) | grep inet | awk '{print $2}' | awk -F: '{print $2}') netmask=255.255.255.192 gateway=$(if route -n | grep -q '^10\.0\.0\.0'; then route -n | grep '^10\.0\.0\.0'; else route -n | grep '^0\.0\.0\.0'; fi | awk '{print $2}') dns=$(grep ^nameserver /etc/resolv.conf | head -1 | awk '{print $2}') mtu=9000 ks=nfs:$1:/backup/ks/backup_boot_root.cfg biosdevname=0 nomodeset pcie_aspm=off" && reboot
fi
EOF
chmod 755 /rescue/backup || $Error

cat /etc/securetty || $Error
cat << 'EOF' | tee /etc/securetty || $Error
console
vc/1
vc/2
vc/3
vc/4
vc/5
vc/6
vc/7
vc/8
vc/9
vc/10
vc/11
tty1
tty2
tty3
tty4
tty5
tty6
tty7
tty8
tty9
tty10
tty11
hvc0
ttyS0
ttyS1
EOF

cat /etc/sysconfig/clock || $Error
cat << 'EOF' | tee /etc/sysconfig/clock || $Error
ZONE="Asia/Tokyo"
EOF
rm -f /etc/localtime || $Error
cp -a /usr/share/zoneinfo/Asia/Tokyo /etc/localtime || $Error

cat /etc/sysconfig/keyboard || $Error
cat << 'EOF' | tee /etc/sysconfig/keyboard || $Error
KEYTABLE="jp106"
MODEL="jp106"
LAYOUT="jp"
KEYBOARDTYPE="pc"
EOF

cat /etc/yum.conf || $Error
sed -i -e '/^assumeyes=.*$/d' -e '/^failovermethod=.*$/d' -e 's/^installonly_limit=.*$/installonly_limit=3/' /etc/yum.conf || $Error

cat /etc/yum.repos.d/CentOS-Base.repo || $Error
if grep -q ^CentOS /etc/system-release; then
  cat << 'EOF' | tee /etc/yum.repos.d/CentOS-Base.repo || $Error
[base]
name=CentOS-6 - Base
baseurl=http://mirrors.service.networklayer.com/centos/6/os/x86_64/
gpgcheck=1
gpgkey=http://mirrors.service.networklayer.com/centos/RPM-GPG-KEY-CentOS-6
exclude=centos-release cluster-glue* corosync* heartbeat* ldirectord libesmtp* pacemaker* resource-agents* drbd* libevent*

[updates]
name=CentOS-6 - Updates
baseurl=http://mirrors.service.networklayer.com/centos/6/updates/x86_64/
gpgcheck=1
gpgkey=http://mirrors.service.networklayer.com/centos/RPM-GPG-KEY-CentOS-6
exclude=centos-release cluster-glue* corosync* heartbeat* ldirectord libesmtp* pacemaker* resource-agents* drbd* libevent*

[extras]
name=CentOS-6 - Extras
baseurl=http://mirrors.service.networklayer.com/centos/6/extras/x86_64/
gpgcheck=1
gpgkey=http://mirrors.service.networklayer.com/centos/RPM-GPG-KEY-CentOS-6
exclude=centos-release centos-release-SCL centos-release-cr centos-release-xen 

[centosplus]
name=CentOS-6 - Plus
baseurl=http://mirrors.service.networklayer.com/centos/6/centosplus/x86_64/
gpgcheck=1
enabled=0
gpgkey=http://mirrors.service.networklayer.com/centos/RPM-GPG-KEY-CentOS-6

[contrib]
name=CentOS-6 - Contrib
baseurl=http://mirrors.service.networklayer.com/centos/6/contrib/x86_64/
gpgcheck=1
enabled=0
gpgkey=http://mirrors.service.networklayer.com/centos/RPM-GPG-KEY-CentOS-6
EOF
  rm -rf /etc/yum.repos.d/CentOS-Base.repo.orig* || $Error
  cat << 'EOF' | tee /etc/yum.repos.d/CentOS-SCL.repo || $Error
[scl]
name=CentOS-6 - SCL
baseurl=http://mirrors.service.networklayer.com/centos/6/SCL/x86_64/
gpgcheck=1
enabled=1
gpgkey=http://mirrors.service.networklayer.com/centos/RPM-GPG-KEY-CentOS-6
EOF
  cat /etc/yum.repos.d/CentOS-Vault.repo || $Error
  cat << 'EOF' | tee /etc/yum.repos.d/CentOS-Vault.repo || $Error
# CentOS-Vault.repo
#
# CentOS Vault holds packages from previous releases within the same CentOS Version
# these are packages obsoleted by the current release and should usually not
# be used in production
#-----------------

[C6.0-base]
name=CentOS-6.0 - Base
baseurl=http://vault.centos.org/6.0/os/$basearch/
gpgcheck=1
gpgkey=http://mirrors.service.networklayer.com/centos/RPM-GPG-KEY-CentOS-6
enabled=0
exclude=centos-release cluster-glue* corosync* heartbeat* ldirectord libesmtp* pacemaker* resource-agents* drbd* libevent*

[C6.0-updates]
name=CentOS-6.0 - Updates
baseurl=http://vault.centos.org/6.0/updates/$basearch/
gpgcheck=1
gpgkey=http://mirrors.service.networklayer.com/centos/RPM-GPG-KEY-CentOS-6
enabled=0
exclude=centos-release cluster-glue* corosync* heartbeat* ldirectord libesmtp* pacemaker* resource-agents* drbd* libevent*

[C6.0-extras]
name=CentOS-6.0 - Extras
baseurl=http://vault.centos.org/6.0/extras/$basearch/
gpgcheck=1
gpgkey=http://mirrors.service.networklayer.com/centos/RPM-GPG-KEY-CentOS-6
enabled=0
exclude=centos-release centos-release-SCL centos-release-cr centos-release-xen 

[C6.0-contrib]
name=CentOS-6.0 - Contrib
baseurl=http://vault.centos.org/6.0/contrib/$basearch/
gpgcheck=1
gpgkey=http://mirrors.service.networklayer.com/centos/RPM-GPG-KEY-CentOS-6
enabled=0

[C6.0-centosplus]
name=CentOS-6.0 - CentOSPlus
baseurl=http://vault.centos.org/6.0/centosplus/$basearch/
gpgcheck=1
gpgkey=http://mirrors.service.networklayer.com/centos/RPM-GPG-KEY-CentOS-6
enabled=0
#-----------------

[C6.1-base]
name=CentOS-6.1 - Base
baseurl=http://vault.centos.org/6.1/os/$basearch/
gpgcheck=1
gpgkey=http://mirrors.service.networklayer.com/centos/RPM-GPG-KEY-CentOS-6
enabled=0
exclude=centos-release cluster-glue* corosync* heartbeat* ldirectord libesmtp* pacemaker* resource-agents* drbd* libevent*

[C6.1-updates]
name=CentOS-6.1 - Updates
baseurl=http://vault.centos.org/6.1/updates/$basearch/
gpgcheck=1
gpgkey=http://mirrors.service.networklayer.com/centos/RPM-GPG-KEY-CentOS-6
enabled=0
exclude=centos-release cluster-glue* corosync* heartbeat* ldirectord libesmtp* pacemaker* resource-agents* drbd* libevent*

[C6.1-extras]
name=CentOS-6.1 - Extras
baseurl=http://vault.centos.org/6.1/extras/$basearch/
gpgcheck=1
gpgkey=http://mirrors.service.networklayer.com/centos/RPM-GPG-KEY-CentOS-6
enabled=0
exclude=centos-release centos-release-SCL centos-release-cr centos-release-xen 

[C6.1-contrib]
name=CentOS-6.1 - Contrib
baseurl=http://vault.centos.org/6.1/contrib/$basearch/
gpgcheck=1
gpgkey=http://mirrors.service.networklayer.com/centos/RPM-GPG-KEY-CentOS-6
enabled=0

[C6.1-centosplus]
name=CentOS-6.1 - CentOSPlus
baseurl=http://vault.centos.org/6.1/centosplus/$basearch/
gpgcheck=1
gpgkey=http://mirrors.service.networklayer.com/centos/RPM-GPG-KEY-CentOS-6
enabled=0
#-----------------

[C6.2-base]
name=CentOS-6.2 - Base
baseurl=http://vault.centos.org/6.2/os/$basearch/
gpgcheck=1
gpgkey=http://mirrors.service.networklayer.com/centos/RPM-GPG-KEY-CentOS-6
enabled=0
exclude=centos-release cluster-glue* corosync* heartbeat* ldirectord libesmtp* pacemaker* resource-agents* drbd* libevent*

[C6.2-updates]
name=CentOS-6.2 - Updates
baseurl=http://vault.centos.org/6.2/updates/$basearch/
gpgcheck=1
gpgkey=http://mirrors.service.networklayer.com/centos/RPM-GPG-KEY-CentOS-6
enabled=0
exclude=centos-release cluster-glue* corosync* heartbeat* ldirectord libesmtp* pacemaker* resource-agents* drbd* libevent*

[C6.2-extras]
name=CentOS-6.2 - Extras
baseurl=http://vault.centos.org/6.2/extras/$basearch/
gpgcheck=1
gpgkey=http://mirrors.service.networklayer.com/centos/RPM-GPG-KEY-CentOS-6
enabled=0
exclude=centos-release centos-release-SCL centos-release-cr centos-release-xen 

[C6.2-contrib]
name=CentOS-6.2 - Contrib
baseurl=http://vault.centos.org/6.2/contrib/$basearch/
gpgcheck=1
gpgkey=http://mirrors.service.networklayer.com/centos/RPM-GPG-KEY-CentOS-6
enabled=0

[C6.2-centosplus]
name=CentOS-6.2 - CentOSPlus
baseurl=http://vault.centos.org/6.2/centosplus/$basearch/
gpgcheck=1
gpgkey=http://mirrors.service.networklayer.com/centos/RPM-GPG-KEY-CentOS-6
enabled=0
#-----------------

[C6.3-base]
name=CentOS-6.3 - Base
baseurl=http://vault.centos.org/6.3/os/$basearch/
gpgcheck=1
gpgkey=http://mirrors.service.networklayer.com/centos/RPM-GPG-KEY-CentOS-6
enabled=0
exclude=centos-release cluster-glue* corosync* heartbeat* ldirectord libesmtp* pacemaker* resource-agents* drbd* libevent*

[C6.3-updates]
name=CentOS-6.3 - Updates
baseurl=http://vault.centos.org/6.3/updates/$basearch/
gpgcheck=1
gpgkey=http://mirrors.service.networklayer.com/centos/RPM-GPG-KEY-CentOS-6
enabled=0
exclude=centos-release cluster-glue* corosync* heartbeat* ldirectord libesmtp* pacemaker* resource-agents* drbd* libevent*

[C6.3-extras]
name=CentOS-6.3 - Extras
baseurl=http://vault.centos.org/6.3/extras/$basearch/
gpgcheck=1
gpgkey=http://mirrors.service.networklayer.com/centos/RPM-GPG-KEY-CentOS-6
enabled=0
exclude=centos-release centos-release-SCL centos-release-cr centos-release-xen 

[C6.3-contrib]
name=CentOS-6.3 - Contrib
baseurl=http://vault.centos.org/6.3/contrib/$basearch/
gpgcheck=1
gpgkey=http://mirrors.service.networklayer.com/centos/RPM-GPG-KEY-CentOS-6
enabled=0

[C6.3-centosplus]
name=CentOS-6.3 - CentOSPlus
baseurl=http://vault.centos.org/6.3/centosplus/$basearch/
gpgcheck=1
gpgkey=http://mirrors.service.networklayer.com/centos/RPM-GPG-KEY-CentOS-6
enabled=0
#-----------------

[C6.4-base]
name=CentOS-6.4 - Base
baseurl=http://vault.centos.org/6.4/os/$basearch/
gpgcheck=1
gpgkey=http://mirrors.service.networklayer.com/centos/RPM-GPG-KEY-CentOS-6
enabled=0
exclude=centos-release cluster-glue* corosync* heartbeat* ldirectord libesmtp* pacemaker* resource-agents* drbd* libevent*

[C6.4-updates]
name=CentOS-6.4 - Updates
baseurl=http://vault.centos.org/6.4/updates/$basearch/
gpgcheck=1
gpgkey=http://mirrors.service.networklayer.com/centos/RPM-GPG-KEY-CentOS-6
enabled=0
exclude=centos-release cluster-glue* corosync* heartbeat* ldirectord libesmtp* pacemaker* resource-agents* drbd* libevent*

[C6.4-extras]
name=CentOS-6.4 - Extras
baseurl=http://vault.centos.org/6.4/extras/$basearch/
gpgcheck=1
gpgkey=http://mirrors.service.networklayer.com/centos/RPM-GPG-KEY-CentOS-6
enabled=0
exclude=centos-release centos-release-SCL centos-release-cr centos-release-xen 

[C6.4-contrib]
name=CentOS-6.4 - Contrib
baseurl=http://vault.centos.org/6.4/contrib/$basearch/
gpgcheck=1
gpgkey=http://mirrors.service.networklayer.com/centos/RPM-GPG-KEY-CentOS-6
enabled=0

[C6.4-centosplus]
name=CentOS-6.4 - CentOSPlus
baseurl=http://vault.centos.org/6.4/centosplus/$basearch/
gpgcheck=1
gpgkey=http://mirrors.service.networklayer.com/centos/RPM-GPG-KEY-CentOS-6
enabled=0
EOF
fi

cat << 'EOF' | tee /etc/yum.repos.d/elrepo.repo || $Error
[elrepo]
name=ELRepo.org Community Enterprise Linux Repository - el6
baseurl=http://elrepo.org/linux/elrepo/el6/x86_64/
        http://mirrors.coreix.net/elrepo/elrepo/el6/x86_64/
        http://jur-linux.org/download/elrepo/elrepo/el6/x86_64/
        http://repos.lax-noc.com/elrepo/elrepo/el6/x86_64/
        http://mirror.ventraip.net.au/elrepo/elrepo/el6/x86_64/
mirrorlist=http://mirrors.elrepo.org/mirrors-elrepo.el6
enabled=0
gpgcheck=1
gpgkey=http://www.elrepo.org/RPM-GPG-KEY-elrepo.org
protect=0
exclude=elrepo-release
EOF

cat << 'EOF' | tee /etc/yum.repos.d/epel.repo || $Error
[epel]
name=Extra Packages for Enterprise Linux 6 - x86_64
#baseurl=http://ftp.jaist.ac.jp/pub/Linux/Fedora/epel/6/x86_64/
mirrorlist=https://mirrors.fedoraproject.org/metalink?repo=epel-6&arch=x86_64
failovermethod=priority
enabled=0
gpgcheck=1
gpgkey=http://ftp.riken.jp/Linux/fedora/epel/RPM-GPG-KEY-EPEL-6
exclude=epel-release cluster-glue* corosync* heartbeat* ldirectord libesmtp* pacemaker* resource-agents* drbd* armadillo* python-argcomplete python-argh v8 v8-devel zabbix* sl
EOF

cat << 'EOF' | tee /etc/yum.repos.d/remi.repo || $Error
[remi]
name=Les RPM de remi pour Enterprise Linux 6 - x86_64
#baseurl=http://rpms.famillecollet.com/enterprise/6/remi/x86_64/
mirrorlist=http://rpms.famillecollet.com/enterprise/6/remi/mirror
enabled=0
gpgcheck=1
gpgkey=http://rpms.famillecollet.com/RPM-GPG-KEY-remi
exclude=remi-release libevent*

[remi-php55]
name=Les RPM de remi de PHP 5.5 pour Enterprise Linux 6 - x86_64
#baseurl=http://rpms.famillecollet.com/enterprise/6/php55/x86_64/
mirrorlist=http://rpms.famillecollet.com/enterprise/6/php55/mirror
# WARNING: If you enable this repository, you must also enable "remi"
enabled=0
gpgcheck=1
gpgkey=http://rpms.famillecollet.com/RPM-GPG-KEY-remi

[remi-php56]
name=Les RPM de remi de PHP 5.6 pour Enterprise Linux 6 - x86_64
#baseurl=http://rpms.famillecollet.com/enterprise/6/php56/x86_64/
mirrorlist=http://rpms.famillecollet.com/enterprise/6/php56/mirror
# WARNING: If you enable this repository, you must also enable "remi"
enabled=0
gpgcheck=1
gpgkey=http://rpms.famillecollet.com/RPM-GPG-KEY-remi
EOF

cat << 'EOF' | tee /etc/yum.repos.d/mysql56.repo || $Error
[MySQL56]
name=MySQL 5.6 for Oracle Linux 6 (x86_64)
baseurl=http://public-yum.oracle.com/repo/OracleLinux/OL6/MySQL56/x86_64/
gpgkey=http://public-yum.oracle.com/RPM-GPG-KEY-oracle-ol6
gpgcheck=1
enabled=0
EOF

cat << 'EOF' | tee /etc/yum.repos.d/pgdg-93-centos.repo || $Error
[pgdg93]
name=PostgreSQL 9.3 rhel6 - x86_64
baseurl=http://yum.postgresql.org/9.3/redhat/rhel-6-x86_64
enabled=0
gpgcheck=1
gpgkey=http://yum.postgresql.org/RPM-GPG-KEY-PGDG-93
exclude=pgdg-centos93 pgdg-oraclelinux93 pgdg-redhat93 pgdg-sl93 usda-r18 libevent-devel
EOF

cat << 'EOF' | tee /etc/yum.repos.d/rpmforge.repo || $Error
[rpmforge]
name = RHEL 6 - RPMforge.net - dag
baseurl = http://apt.sw.be/redhat/el6/en/x86_64/rpmforge
mirrorlist = http://mirrorlist.repoforge.org/el6/mirrors-rpmforge
enabled = 0
gpgkey = http://apt.sw.be/RPM-GPG-KEY.dag.txt
gpgcheck = 1
includepkgs=lv
EOF

cat << 'EOF' | sudo tee /etc/yum.repos.d/zabbix.repo || $Error
[zabbix]
name=Zabbix Official Repository - x86_64
baseurl=http://repo.zabbix.com/zabbix/2.2/rhel/6/x86_64/
enabled=0
gpgcheck=1
gpgkey=http://repo.zabbix.com/RPM-GPG-KEY-ZABBIX
exclude=zabbix-release zabbix-proxy* zabbix-server-pgsql zabbix-server-sqlite3 zabbix-web-pgsql zabbix-web-sqlite3

[zabbix-non-supported]
name=Zabbix Official Repository non-supported - x86_64
baseurl=http://repo.zabbix.com/non-supported/rhel/6/x86_64/
enabled=0
gpgkey=http://repo.zabbix.com/RPM-GPG-KEY-ZABBIX
gpgcheck=1
exclude=zabbix-release
EOF

cat << 'EOF' | tee /etc/yum.repos.d/glusterfs-epel.repo || $Error
[glusterfs-epel]
name=GlusterFS is a clustered file-system capable of scaling to several petabytes.
baseurl=http://download.gluster.org/pub/gluster/glusterfs/LATEST/EPEL.repo/epel-6/x86_64/
enabled=0
skip_if_unavailable=1
gpgcheck=1
gpgkey=http://download.gluster.org/pub/gluster/glusterfs/LATEST/EPEL.repo/pub.key

[glusterfs-noarch-epel]
name=GlusterFS is a clustered file-system capable of scaling to several petabytes.
baseurl=http://download.gluster.org/pub/gluster/glusterfs/LATEST/EPEL.repo/epel-6/noarch
enabled=0
skip_if_unavailable=1
gpgcheck=1
gpgkey=http://download.gluster.org/pub/gluster/glusterfs/LATEST/EPEL.repo/pub.key
EOF

cat << 'EOF' | tee /etc/yum.repos.d/nginx.repo || $Error
[nginx]
name=nginx repo
baseurl=http://nginx.org/packages/centos/6/x86_64/
enabled=0
gpgkey=http://nginx.org/packages/keys/nginx_signing.key
gpgcheck=1
EOF

rpm -qa | LANG=C sort || $Error
yum -y update || $Error

if [ -d /proc/xen/ ]; then
  yum -y install OpenIPMI ipmitool net-snmp-libs ntp iscsi-initiator-utils || $Error
else
  yum -y remove apr autoconf bind-devel cyrus-sasl-devel db4-cxx expat-devel libc-client mailcap php-common tcl || $Error
  yum -y localinstall https://raw.githubusercontent.com/pcserver-jp/SoftLayer/master/{xe-guest-utilities-6.2.0-1137.x86_64.rpm,xe-guest-utilities-xenstore-6.2.0-1137.x86_64.rpm} || $Error
fi

if [ ! -e /usr/local/sbin/ipmicli ]; then
  wget -q -O /usr/local/sbin/ipmicli http://downloads.service.softlayer.com/ipmi/linux/cli/ipmicli.x86_64 || $Error
  chmod 755 /usr/local/sbin/ipmicli || $Error
fi

if [ ! -d /usr/Adaptec_Event_Monitor/ ]; then
  wget -q http://download.adaptec.com/raid/storage_manager/adaptec_event_monitor_v1_06_21062.zip || $Error
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

cat /usr/Adaptec_Event_Monitor/Email_Notification_Status.cfg || $Error
cat /usr/Adaptec_Event_Monitor/Mail_Recipients.cfg || $Error
cat /usr/Adaptec_Event_Monitor/SMTP_Server_Details.cfg || $Error
cat /usr/Adaptec_Event_Monitor/NRMFSAConfig.xml  || $Error
sed -i -e 's/^nrm.debugMask.*$/nrm.debugMask = 2/' /usr/Adaptec_Event_Monitor/NRMConfig.conf || $Error

yum -y localinstall https://raw.githubusercontent.com/pcserver-jp/stone/master/stone-2.3e-2.3.3.17.el6.x86_64.rpm || $Error
openssl req -new -outform pem -out /etc/pki/tls/certs/stone.pem -newkey rsa:1024 -keyout stone.key -nodes -rand ./rand.pat -x509 -batch -days 36500 || $Error
cat stone.key | tee -a /etc/pki/tls/certs/stone.pem > /dev/null || $Error
chmod 400 /etc/pki/tls/certs/stone.pem || $Error
rm -f stone.key || $Error
groupadd -g 17 stoned || $Error
useradd -u 17 -g stoned -c "Stone Daemon" -d / -s /sbin/nologin -r stoned || $Error
mkdir -p /var/chroot/stoned || $Error
cat << 'EOF' | tee /etc/stoned.conf || $Error
localhost:22 443/ssl
EOF
cat << 'EOF' | tee /etc/init.d/stoned || $Error
#!/bin/bash
#
# stoned        Starts stone daemon.
#
# chkconfig: 2345 99 25
# description: Stone is a TCP/IP repeater in the application layer. \
# It repeats TCP and UDP from inside to outside of a firewall, or \
# from outside to inside.

### BEGIN INIT INFO
# Provides: stoned
# Required-Start: $network $local_fs $remote_fs
# Required-Stop: $network $local_fs $remote_fs
# Should-Start: $syslog
# Should-Stop: $syslog
# Default-Start: 2345
# Default-Stop: 99
# Short-Description: Starts/stop the "stone" daemon
# Description:      Stone is a TCP/IP repeater in the application layer.
#    It repeats TCP and UDP from inside to outside of a firewall, or
#    from outside to inside.
### END INIT INFO

# source function library.
. /etc/init.d/functions

RETVAL=0
prog="stone"
lockfile=/var/lock/subsys/$prog
STONE_BIN="/usr/bin/stone"
STONE_CONF="/etc/${prog}d.conf"
STONE_CHROOT=/var/chroot/${prog}d
STONE_OPTS="-l -C $STONE_CONF -o stoned -g stoned -t $STONE_CHROOT"
PIDFILE=/var/run/${prog}.pid

start()
{
  [ "$EUID" != "0" ] && exit 4
  echo -n $"Starting $prog: "
  daemon $STONE_BIN $STONE_OPTS -D -i $PIDFILE
  RETVAL=$?
  echo
  [ $RETVAL -eq 0 ] && touch $lockfile
  return $RETVAL
}

stop()
{
  [ "$EUID" != "0" ] && exit 4
  echo -n $"Shutting down $prog: "
  killproc -p $PIDFILE $STONE_BIN
  RETVAL=$?
  echo
  [ $RETVAL -eq 0 ] && rm -f $lockfile
  return $RETVAL
}

case "$1" in
  start)
    start
    ;;
  stop)
    stop
    ;;
  restart)
    stop
    start
    ;;
  status)
    status $prog
    ;;
  *)
    echo $"Usage: $0 {start|stop|restart}"
    RETVAL=1
esac

exit $RETVAL
EOF
chmod 755 /etc/init.d/stoned || $Error

yum -y --enablerepo=epel,pgdg93 install \
 aide \
 apachetop \
 arp-scan \
 arptables_jf \
 arpwatch \
 atop \
 autossh \
 bash-completion \
 bonnie++ \
 btrfs-progs \
 cachefilesd \
 chkrootkit \
 colordiff \
 colorize \
 compat-libevent14 \
 compat-libevent14-devel \
 conntrack-tools \
 cpuid \
 createrepo \
 ctags-etags \
 daemonize \
 dd_rescue \
 device-mapper-multipath \
 dhcping \
 dialog \
 disktype \
 dkms \
 dnsmasq \
 dnsperf \
 dnstop \
 dnstracer \
 dos2unix \
 dropwatch \
 dstat \
 dump \
 dwatch \
 ecryptfs-utils \
 elinks \
 ethstatus \
 expect \
 fail2ban \
 fakechroot \
 fakeroot \
 fio \
 fping \
 ftop \
 ftp \
 gdb \
 gnutls-utils \
 haproxy \
 hardlink \
 hatools \
 hddtemp \
 hping3 \
 htop \
 httpd24 \
 httpd24-mod_ssl \
 ifstatus \
 iftop \
 innotop \
 inotify-tools \
 ioping \
 ioprocess \
 iotop \
 iperf3 \
 ipmiutil \
 ipset \
 iptraf \
 iptstate \
 ipvsadm \
 ipwatchd \
 jq \
 keepalived \
 latencytop-tui \
 libevent \
 livecd-tools \
 lm_sensors \
 lm_sensors-sensord \
 logwatch \
 lrzsz \
 lsscsi \
 lsyncd \
 ltrace \
 man-pages-ja \
 mon \
 monit \
 munin \
 munin-async \
 munin-node \
 mx \
 mytop \
 nc \
 net-snmp \
 net-snmp-devel \
 net-snmp-utils \
 netstat-nat \
 nfsometer \
 nfs-utils \
 ngrep \
 nkf \
 nload \
 nmap \
 nscd \
 ntfs-3g \
 ntfsprogs \
 ntop \
 numad \
 nwipe \
 omping \
 OpenIPMI-libs \
 openvpn \
 oprofile \
 p7zip \
 pbzip2 \
 perf \
 perl-Authen-SASL \
 perl-MIME-tools \
 pexpect \
 pipestat \
 powertop \
 pssh \
 pv \
 PyMunin \
 python-setuptools \
 redhat-rpm-config \
 repoview \
 rlwrap \
 rootsh \
 rpm-build \
 rpmconf \
 rpmdevtools \
 rpmlint \
 rpmreaper \
 rpmrebuild \
 rssh \
 rsyslog-gnutls \
 schroot \
 scl-utils-build \
 screen \
 scsi-target-utils \
 sg3_utils \
 sg3_utils-devel \
 slowhttptest \
 sockperf \
 squashfs-tools \
 squid \
 squidGuard \
 ssldump \
 sslscan \
 stress \
 stunnel \
 subnetcalc \
 subversion \
 swatch \
 sysbench \
 sysfsutils \
 syslinux \
 sysprof \
 systemtap-initscript \
 systemtap-sdt-devel \
 systemtap-server \
 tcping \
 tcptraceroute \
 telnet \
 tftp \
 tree \
 unique \
 unix2dos \
 vnstat \
 w3m \
 watchdog \
 wipe \
 xfsdump \
 xfsprogs-qa-devel \
 || $Error

# memcached \
# redis \
# samba4\* \

#yum -y install \
# httpd24* \
# mariadb55* \
# mysql55* \
# nodejs010* \
# perl516* \
# php54* \
# postgresql92* \
# python33* \
# ruby193* \
# v8314* \
# libyaml-devel \
# || $Error
## python27*

#yum -y --enablerepo=MySQL56 install mysql-server mysql-devel mysql-test mysql-bench || $Error
yum -y --enablerepo=epel,remi install mysql-server mysql-devel mysql-test mysql-bench || $Error

yum -y localinstall http://www.percona.com/downloads/XtraBackup/LATEST/binary/redhat/6/x86_64/percona-xtrabackup-2.2.4-5004.el6.x86_64.rpm || $Error

yum -y localinstall http://www.percona.com/downloads/percona-toolkit/LATEST/RPM/percona-toolkit-2.2.11-1.noarch.rpm || $Error

#yum -y localinstall file:///C:/Users/dba/Documents/Downloads/percona-zabbix-templates-1.1.4-1.noarch.rpm || $Error

yum -y --enablerepo=pgdg93 install postgresql93\* || $Error

#yum -y install --enablerepo=epel,pgdg93 \
# CGAL \
# armadillo \
# armadillo-devel \
# barman \
# boxinfo \
# check_postgres \
# cstore_fdw_93 \
# gdal \
# gdal-devel \
# gdal-doc \
# gdal-java \
# gdal-javadoc \
# gdal-libs \
# gdal-perl \
# gdal-python \
# gdal-ruby \
# geos \
# geos-devel \
# geos-python \
# gpsbabel \
# ip4r93 \
# libgeotiff \
# libgeotiff-devel \
# libmemcached \
# libmemcached-devel \
# libpqxx \
# libpqxx-devel \
# mongo_fdw93 \
# pagila93 \
# pg_activity \
# pg_catcheck93 \
# pg_jobmon93 \
# pg_partman93 \
# pg_repack93 \
# pg_top93 \
# pgadmin3_93 \
# pgadmin3_93-docs \
# pgbadger \
# pgbouncer \
# pgcluu \
# pgespresso93 \
# pgfincore93 \
# pgloader \
# pgmemcache-93 \
# pgpool-II-93 \
# pgpool-II-93-devel \
# pgrouting_93 \
# pgtap93 \
# pgxnclient \
# plpgsql_check_93 \
# plproxy93 \
# plr93 \
# plsh93 \
# plv8_93 \
# postgis2_93 \
# postgis2_93-client \
# postgis2_93-devel \
# postgis2_93-docs \
# postgis2_93-utils \
# postgresql_autodoc \
# proj \
# proj-devel \
# proj-epsg \
# proj-nad \
# python-argcomplete \
# python-argh \
# python-argparse \
# python-psycopg2 \
# python-psycopg2-doc \
# python-psycopg2-test \
# repmgr \
# skytools-93 \
# skytools-93-modules \
# slony1-93 \
# split_postgres_dump \
# tail_n_mail \
# v8 \
# v8-devel \
# || $Error

#yum -y install --enablerepo=epel,pgdg93 \
# emaj \
# phpPgAdmin \
# || $Error

##Requires: perl(DBD::Oracle)
#yum install --enablerepo=epel,pgdg93 ora2pg || $Error

##Requires: perl-Pod-Usage
##Broken: perl pachage has /usr/share/perl5/Pod/Usage.pm
#yum install --enablerepo=epel,pgdg93 pg_comparator93 || $Error

##Requires: perl-Mojolicious
##ftp://ftp.pbone.net/mirror/ftp5.gwdg.de/pub/opensuse/repositories/home:/viliampucik:/rhel/RedHat_RHEL-6/home_viliampucik_rhel.repo
#cat << 'EOF' | tee /etc/yum.repos.d/home_viliampucik_rhel.repo
#[home_viliampucik_rhel]
#name=home:viliampucik:rhel (RedHat_RHEL-6)
#type=rpm-md
#baseurl=http://download.opensuse.org/repositories/home:/viliampucik:/rhel/RedHat_RHEL-6/
#gpgcheck=1
#gpgkey=http://download.opensuse.org/repositories/home:/viliampucik:/rhel/RedHat_RHEL-6/repodata/repomd.xml.key
#enabled=0
#includepkgs=perl-Mojolicious
#EOF
#yum -y install --enablerepo=epel,pgdg93,home_viliampucik_rhel powa_93 powa_93-ui || $Error

yum -y --enablerepo=rpmforge install lv || $Error

yum -y --disablerepo=\* --enablerepo=elrepo install drbd84-utils kmod-drbd84 || $Error

wget -q http://iij.dl.sourceforge.jp/linux-ha/61791/pacemaker-1.0.13-2.1.el6.x86_64.repo.tar.gz || $Error
tar xzvf pacemaker-1.0.13-2.1.el6.x86_64.repo.tar.gz -C /tmp/ || $Error
yum -y -c /tmp/pacemaker-1.0.13-2.1.el6.x86_64.repo/pacemaker.repo install pacemaker heartbeat pm_extras pm_diskd || $Error
rm -rf /tmp/pacemaker-1.0.13-2.1.el6.x86_64.repo pacemaker-1.0.13-2.1.el6.x86_64.repo.tar.gz || $Error

cat << 'EOF' | tee /etc/rsyslog.conf || $Error
$umask 0000
$FileCreateMode 0640
$DirCreateMode 0750
$FileOwner root
$FileGroup wheel
$ModLoad imuxsock
$ModLoad imklog
$ModLoad immark
$ModLoad imudp
$UDPServerRun 514
$ModLoad imtcp
$InputTCPServerRun 514
$RepeatedMsgReduction off
$SystemLogRateLimitInterval 0
$MaxMessageSize 1048576
$ActionFileDefaultTemplate RSYSLOG_TraditionalFileFormat
#$ActionFileEnableSync on

#$WorkDirectory /var/lib/rsyslog
#$ActionQueueFileName fwdRule1
#$ActionQueueMaxDiskSpace 1g
#$ActionQueueSaveOnShutdown on
#$ActionQueueType LinkedList
#$ActionResumeRetryCount -1

$IncludeConfig /etc/rsyslog.d/*.conf

$template DynamicFileName0,"/var/log/all/operation/%programname:::secpath-replace%.log"
$template DynamicFileName1,"/var/log/all/%$year%%$month%%$day%/%programname:::secpath-replace%.log"
$template DynamicFileName2,"/var/log/all/%$year%%$month%%$day%/all.log"

local0.*                                                ?DynamicFileName0
*.*;local0.none                                         ?DynamicFileName1
*.*;local0.none                                         ?DynamicFileName2

:fromhost-ip, !isequal, "127.0.0.1" ~
#*.info @@remote-host1:514
#*.info @@remote-host2:514

*.emerg                                                 *

#kern.*                                                 /dev/console

mail.*                                                  -/var/log/maillog
& ~
authpriv.*                                              /var/log/secure
& ~
cron.*                                                  /var/log/cron
& ~
#local0.*                                                /var/log/operation.log
#& ~
local0.* ~
local1.*                                                /var/log/local1.log
& ~
local2.*                                                /var/log/local2.log
& ~
local3.*                                                /var/log/local3.log
& ~
local4.*                                                /var/log/local4.log
& ~
local5.*                                                /var/log/local5.log
& ~
local6.*                                                /var/log/local6.log
& ~
local7.*                                                /var/log/boot.log
& ~
uucp,news.crit                                          /var/log/spooler
& ~

*.info                                                  /var/log/messages
EOF

#local0: operation.log
#local1: 
#local2: 
#local3: 
#local4: ipmievd
#local5: 
#local6: 
#local7: boot.log

cat << 'EOF' | tee /etc/cron.d/rsyslog-delete || $Error
SHELL=/bin/bash
PATH=/sbin:/bin:/usr/sbin:/usr/bin
MAILTO=root
HOME=/
40 4 * * * root find /var/log/all/ -daystart -mtime +365 -exec rm -rf {} \; > /dev/null 2>&1 || :
EOF

cat << 'EOF' | tee /etc/logrotate.d/syslog
/var/log/cron
/var/log/maillog
/var/log/messages
/var/log/ip_tables.log
/var/log/operation.log
/var/log/local0.log
/var/log/local1.log
/var/log/local2.log
/var/log/local3.log
/var/log/local4.log
/var/log/local5.log
/var/log/local6.log
/var/log/secure
/var/log/spooler
/var/log/haproxy.log
{
    sharedscripts
    postrotate
        /bin/kill -HUP `cat /var/run/syslogd.pid 2> /dev/null` 2> /dev/null || true
    endscript
}
EOF

cat << 'EOF' | tee /etc/logrotate.conf
daily
rotate 365
create 0640 root wheel
dateext
#compress
#delaycompress
notifempty
missingok
include /etc/logrotate.d
/var/log/wtmp {
  monthly
  create 0664 root utmp
  minsize 1M
  rotate 1
}
/var/log/btmp {
  missingok
  monthly
  create 0600 root utmp
  rotate 1
}
EOF

cat << 'EOF' | tee /etc/logrotate.d/aide
/var/log/aide/*.log {
  copytruncate
}
EOF

cat << 'EOF' | tee /etc/logrotate.d/dracut
/var/log/dracut.log {
  create 0600 root root
}
EOF

cat << 'EOF' | tee /etc/logrotate.d/fail2ban
/var/log/fail2ban.log {
  postrotate
    /usr/bin/fail2ban-client flushlogs 1>/dev/null || true
  endscript
}
EOF

cat << 'EOF' | tee /etc/logrotate.d/haproxy

EOF

cat << 'EOF' | tee /etc/logrotate.d/httpd24-httpd
/var/log/httpd24/*log {
  sharedscripts
  postrotate
    /sbin/service httpd24-httpd reload > /dev/null 2>/dev/null || true
  endscript
}
EOF

cat << 'EOF' | tee /etc/logrotate.d/iptraf
/var/log/iptraf/*.log {
  create 0600 root root
}
EOF

cat << 'EOF' | tee /etc/logrotate.d/iscsiuiolog
/var/log/iscsiuio.log {
  sharedscripts
  postrotate
    pkill -USR1 iscsiuio 2> /dev/null || true
  endscript
}
EOF

cat << 'EOF' | tee /etc/logrotate.d/lsyncd
/var/log/lsyncd/*log {
  sharedscripts
}
EOF

cat << 'EOF' | tee /etc/logrotate.d/monit
/var/log/monit {
  create 0644 root root
  postrotate
    /sbin/service monit condrestart > /dev/null 2>&1 || :
  endscript
}
EOF

cat << 'EOF' | tee /etc/logrotate.d/numad
/var/log/numad.log {
  copytruncate
  maxage 60
  size 1M
}
EOF

cat << 'EOF' | tee /etc/logrotate.d/psacct
/var/account/pacct {
#prerotate loses accounting records, let's no
#  prerotate
#    /usr/sbin/accton
#  endscript
  create 0600 root root
  postrotate
    /usr/sbin/accton /var/account/pacct
  endscript
}
EOF

#cat << 'EOF' | tee /etc/logrotate.d/redis
#/var/log/redis/redis.log {
#  copytruncate
#}
#EOF

#cat << 'EOF' | tee /etc/logrotate.d/samba
#/var/log/samba/* {
#  olddir /var/log/samba/old
#  copytruncate
#}
#EOF

cat << 'EOF' | tee /etc/logrotate.d/squid
/var/log/squid/*.log {
  sharedscripts
  postrotate
    # Asks squid to reopen its logs. (log_rotate 0 is set in squid.conf)
    # errors redirected to make it silent if squid is not running
    /usr/sbin/squid -k rotate 2>/dev/null
    # Wait a little to allow Squid to catch up before the logs is compressed
    sleep 1
  endscript
}
EOF

cat << 'EOF' | tee /etc/logrotate.d/squidGuard
/var/log/squid/squidGuard.log {
  missingok
}
EOF

cat << 'EOF' | tee /etc/logrotate.d/stap-server
/var/log/stap-server/log {
  create 0664 stap-server stap-server
}
EOF

cat << 'EOF' | tee /etc/logrotate.d/yum
/var/log/yum.log {
  create 0600 root root
}
EOF

cat /etc/sysconfig/ntpd || $Error
cat << 'EOF' | tee /etc/sysconfig/ntpd || $Error
# Drop root to id 'ntp:ntp' by default.
OPTIONS="-4 -x -u ntp:ntp -p /var/run/ntpd.pid -g"
EOF
cat /etc/ntp.conf || $Error
cat << 'EOF' | tee /etc/ntp.conf || $Error
driftfile /var/lib/ntp/drift
restrict default kod nomodify notrap nopeer noquery
restrict 127.0.0.1
server -4 10.0.77.54 iburst
includefile /etc/ntp/crypto/pw
keys /etc/ntp/keys
EOF

easy_install softlayer || $Error

if [ ! -e /home/$MY_SL_ADMIN/.softlayer ]; then
  touch /home/$MY_SL_ADMIN/.softlayer || $Error
  chmod 600 /home/$MY_SL_ADMIN/.softlayer || $Error
  chown $MY_SL_ADMIN:$MY_SL_ADMIN /home/$MY_SL_ADMIN/.softlayer || $Error
  cat << EOF | tee /home/$MY_SL_ADMIN/.softlayer || $Error
[softlayer]
username = $SL_ACCOUNT
api_key = $SL_API_KEY
endpoint_url = https://api.service.softlayer.com/xmlrpc/v3.1
timeout = 10
EOF
  touch /home/$MY_SL_ADMIN/.softlayer.user || $Error
  chmod 600 /home/$MY_SL_ADMIN/.softlayer.user || $Error
  chown $MY_SL_ADMIN:$MY_SL_ADMIN /home/$MY_SL_ADMIN/.softlayer.user || $Error
  echo "user = SL_ACCOUNT:$SL_API_KEY" | tee /home/$MY_SL_ADMIN/.softlayer.user || $Error
fi

cat << EOF | tee /usr/local/bin/sendalert || $Error
#!/usr/bin/perl

use strict;
use MIME::Entity;
use Net::SMTP;
use Encode;

my \$username = '$MAIL_USER';
my \$password = '$MAIL_PW';
my \$hello = '$MAIL_HELLO';
my \$from = '$MAIL_FROM';
EOF
cat << 'EOF' | tee -a /usr/local/bin/sendalert || $Error

my $to = $ARGV[0];
my $subject = encode( "MIME-Header-ISO_2022_JP", $ARGV[1] );
my $text = $ARGV[2];
my $mime = MIME::Entity->build(Type => 'multipart/alternative', Encoding => '-SUGGEST', From => $from, To => $to, Subject => $subject);
$mime->attach(Type => 'text/plain', Encoding =>'-SUGGEST', Data => $text);
my $smtp = Net::SMTP->new('smtp.sendgrid.net', Port=> 587, Timeout => 20, Hello => $hello);
$smtp->auth($username, $password);
$smtp->mail($from);
$smtp->to($to);
$smtp->data($mime->stringify);
$smtp->quit();
EOF
chmod 700 /usr/local/bin/sendalert || $Error

cat /etc/sysconfig/ipmi || $Error
sed -i -e 's/^IPMI_WATCHDOG=.*$/IPMI_WATCHDOG=yes/' /etc/sysconfig/ipmi || $Error
sed -i -e 's/^IPMI_WATCHDOG_OPTIONS=.*$/IPMI_WATCHDOG_OPTIONS="timeout=60 action=reset pretimeout=30 preaction=pre_int preop=preop_panic"/' /etc/sysconfig/ipmi || $Error
cat /etc/modprobe.d/blacklist.conf || $Error
sed -i -e '/^blacklist iTCO_wdt$/d' /etc/modprobe.d/blacklist.conf || $Error
sed -i -e 's/^# watchdog drivers/# watchdog drivers\nblacklist iTCO_wdt/' /etc/modprobe.d/blacklist.conf || $Error

cat /etc/watchdog.conf || $Error
sed -i -e 's/^#watchdog-device/watchdog-device/' /etc/watchdog.conf || $Error

cat << 'EOF' | tee /etc/modprobe.d/softdog.conf || $Error
alias char-major-10-130 softdog
options softdog soft_margin=60
EOF
cat /etc/sysconfig/watchdog || $Error
cat << 'EOF' | tee /etc/sysconfig/watchdog || $Error
VERBOSE=no
[ -d /proc/xen/ ] && modprobe softdog
EOF

vnstat --testkernel || $Error
NICs="$(vnstat --iflist | sed -n 's/^Available interfaces: //p')"
for i in $NICs
do
  vnstat -u -i $i || $Error
done
if [ -r /var/lib/vnstat/bond0 ]; then
  cat /etc/vnstat.conf || $Error
  sed -i -e 's/^Interface .*$/Interface "bond0"/' /etc/vnstat.conf || $Error
fi

NICs=$(echo $NICs | tr ' ' ,)

cat /etc/ntop.conf || $Error
cat << EOF | tee /etc/ntop.conf || $Error
--user=ntop
#--use-syslog=local1
--access-log-file=/var/log/ntop.access
#--pcap-log=ntop.pcap
--db-file-path=/var/lib/ntop
--trace-level=3
--http-server=0
--https-server=0.0.0.0:3001
--local-subnets=10.0.0.0/8
--skip-version-check=yes
--interface=$NICs
EOF
sed -i -e 's%^pidfile=.*$%pidfile=/var/lib/ntop/ntop.pid%' /etc/init.d/ntop || $Error
#sed -i -e 's/config --daemon/config --use-syslog=local1 --daemon/' /etc/init.d/ntop || $Error
ntop --set-admin-password=$MY_NTOP_PW || $Error
pkill ntop || :

#if ! grep /var/log/ntop /etc/rsyslog.conf; then
#  sed -i -e 's%/var/log/local1.log%/var/log/ntop%' /etc/rsyslog.conf || $Error
#  mv /var/log/local1.log /var/log/ntop 2> /dev/null || :
#  /etc/init.d/rsyslog restart || $Error
#fi

cat << 'EOF' | tee /etc/logrotate.d/ntop || $Error
/var/log/ntop.access {
  postrotate
    /etc/init.d/ntop reload >/dev/null 2>&1
  endscript
}
EOF

sed -i -e 's/^Listen/#Listen/p' /opt/rh/httpd24/root/etc/httpd/conf/httpd.conf || $Error
sed -i -e 's/443/3003/g' /opt/rh/httpd24/root/etc/httpd/conf.d/ssl.conf || $Error
mv /var/www/html/munin /opt/rh/httpd24/root/var/www/html/ || $Error
ln -s /opt/rh/httpd24/root/var/www/html/munin /var/www/html/munin || $Error

cat << 'EOF' | tee /opt/rh/httpd24/root/etc/httpd/conf.d/status.conf || $Error
#LoadModule status_module modules/mod_status.so
<IfModule mod_status.c>
  ExtendedStatus On
  <Location /server-status>
    SetHandler server-status
    Order deny,allow
    Deny from all
    Allow from 127.0.0.1
    Allow from 10.
  </Location>
</IfModule>
EOF

: | tee /etc/httpd/conf.d/munin.conf || $Error
mv /var/www/cgi-bin/munin-cgi-html /opt/rh/httpd24/root/var/www/cgi-bin/ || $Error
ln -s /opt/rh/httpd24/root/var/www/cgi-bin/munin-cgi-html /var/www/cgi-bin/munin-cgi-html || $Error
mv /var/www/cgi-bin/munin-cgi-graph /opt/rh/httpd24/root/var/www/cgi-bin/ || $Error
ln -s /opt/rh/httpd24/root/var/www/cgi-bin/munin-cgi-graph /var/www/cgi-bin/munin-cgi-graph || $Error
cat << 'EOF' | tee /opt/rh/httpd24/root/etc/httpd/conf.d/munin.conf || $Error
<directory /opt/rh/httpd24/root/var/www/html/munin>
#AuthUserFile /etc/munin/munin-htpasswd
#AuthName "Munin"
#AuthType Basic
#require valid-user
Order Deny,Allow
Deny from all
Allow from 127.0.0.1
Allow from 10.

#LoadModule expires_module modules/mod_expires.so
ExpiresActive On
ExpiresDefault M310
</directory>
ScriptAlias /munin-cgi/munin-cgi-graph /opt/rh/httpd24/root/var/www/cgi-bin/munin-cgi-graph
EOF
#MY_MUNIN_PW=$(dd if=/dev/urandom bs=1 count=6 2> /dev/null | base64)
#echo -n $MY_MUNIN_PW | tee /root/.pw/munin > /dev/null || $Error
#chmod 400 /root/.pw/munin || $Error
#htpasswd -b /etc/munin/munin-htpasswd munin $MY_MUNIN_PW || $Error
sed -i -e 's%^#htmldir.*$%htmldir /opt/rh/httpd24/root/var/www/html/munin%' /etc/munin/munin.conf || $Error

ln -s /usr/share/munin/plugins/munin_stats /etc/munin/plugins/munin_stats

mkdir -p /usr/local/share/munin || $Error
cd /usr/local/share/munin || $Error
git clone https://github.com/munin-monitoring/contrib.git || $Error
cd || $Error

#echo; \
#echo --------------------------------------------------------------------------------; \
#echo /usr/share/munin/plugins/; \
#munin-node-configure --suggest; \
#j=$(for j in /usr/local/share/munin/contrib/plugins/* /usr/local/share/munin/contrib/plugins/*/* /usr/local/share/munin/contrib/plugins/*/*/* /usr/local/share/munin/contrib/plugins/*/*/*/* /usr/local/share/munin/contrib/plugins/*/*/*/*/*; do echo $j; done | sort); \
#for i in $j
#do
#  [ -d $i ] || continue
#  echo
#  echo --------------------------------------------------------------------------------
#  echo $i/
#  munin-node-configure --libdir $i/ --suggest | grep -v ^Plugin | grep -v ^------
#done

cat << 'EOF' | tee /etc/logrotate.d/munin
/var/log/munin/munin-update.log {
  create 640 munin munin
  #su munin munin
}

/var/log/munin/munin-graph.log {
  create 640 munin munin
  #su munin munin
}

/var/log/munin/munin-html.log {
  create 640 munin munin
  #su munin munin
}

/var/log/munin/munin-limits.log {
  create 640 munin munin
  #su munin munin
}
EOF
cat << 'EOF' | tee /etc/logrotate.d/munin-node
/var/log/munin-node/munin-node.log {
  copytruncate
  #su root root
}
EOF

cat /etc/sysconfig/sysstat || $Error
sed -i -e 's/^HISTORY=.*$/HISTORY=366/' /etc/sysconfig/sysstat || $Error

cat /etc/sysconfig/nfs || $Error
cat << 'EOF' | tee /etc/sysconfig/nfs || $Error
MOUNTD_NFS_V2="no"
RQUOTAD_PORT=875
#RPCRQUOTADOPTS=""
#LOCKDARG=
LOCKD_TCPPORT=32803
LOCKD_UDPPORT=32769
RPCNFSDARGS="-N 2"
RPCNFSDCOUNT=16
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
cat /etc/netconfig || $Error
sed -i -e 's/^udp6/#udp6/' -e 's/^tcp6/#tcp6/' /etc/netconfig || $Error

cat << EOF | tee /etc/iscsi/initiatorname.iscsi || $Error
InitiatorName=iqn.1994-05.com.redhat:$(uname -n | awk -F. '{print $1}')
EOF

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

cat << 'EOF' | tee /etc/ha.d/_start || $Error
#!/bin/bash
while ! grep ds:UpToDate/ /proc/drbd > /dev/null;
do
  sleep 1
done
lvremove -f /dev/vg0/drbd0_snap
EOF
chmod 755 /etc/ha.d/_start || $Error

cat << 'EOF' | tee /etc/ha.d/start || $Error
#!/bin/bash
/etc/init.d/heartbeat status && exit 0
if [ ! -b /dev/vg0/drbd0_snap ]; then
  lvcreate --snapshot --extents 100%FREE --name drbd0_snap /dev/vg0/drbd0 || exit 1
fi
/etc/init.d/heartbeat start
nohup /etc/ha.d/_start > /dev/null 2>&1 &
EOF
chmod 755 /etc/ha.d/start || $Error

cat << 'EOF' | tee /etc/ha.d/stop || $Error
#!/bin/bash
/etc/init.d/heartbeat stop
EOF
chmod 755 /etc/ha.d/stop || $Error

cat << 'EOF' | tee /etc/ha.d/which || $Error
#!/bin/bash
crm_mon -rfA1 | grep 'p_vip.*IPsrcaddr'
EOF
chmod 755 /etc/ha.d/which || $Error

cat << 'EOF' | tee /etc/ha.d/switch || $Error
#!/bin/bash
crm_mon -rfA1 | grep 'p_vip.*IPsrcaddr'
crm resource move p_vip 2> /dev/null
echo
echo switching cluster ...
echo
while ! crm_mon -rfA1 | grep -q 'p_vip.*IPsrcaddr.*Stopped';
do
  sleep 1
done
while ! crm_mon -rfA1 | grep -q 'p_vip.*IPsrcaddr.*Started';
do
  sleep 1
done
crm resource unmove p_vip
crm_mon -rfA1 | grep 'p_vip.*IPsrcaddr'
EOF
chmod 755 /etc/ha.d/switch || $Error

cat << 'EOF' | tee /etc/ha.d/record || $Error
#!/bin/bash
crm_mon -rfA1 | grep -v ^Last | grep -v ^Current > /etc/ha.d/_record
crm configure show >> /etc/ha.d/_record
sed -n 's/^.*\(ds:[^ ]* \).*$/\1/p' /proc/drbd >> /etc/ha.d/_record
#ps -o uid,pid,args -e | sed -n 's/^ *0 \(.*[h]eartbeat.*\)$/\1/p' | LANG=C sort >> /etc/ha.d/_record
[ -e /proc/net/bonding/bond0 ] && cat /proc/net/bonding/bond0 >> /etc/ha.d/_record
[ -e /proc/net/bonding/bond1 ] && cat /proc/net/bonding/bond1 >> /etc/ha.d/_record
cat /etc/ha.d/_record
EOF
chmod 755 /etc/ha.d/record || $Error

cat << 'EOF' | tee /etc/ha.d/diff || $Error
#!/bin/bash
if [ ! -e /etc/ha.d/_record ]; then
  echo /etc/ha.d/record was not executed.
  exit 1
fi
crm_mon -rfA1 | grep -v ^Last | grep -v ^Current > /etc/ha.d/_now
crm configure show >> /etc/ha.d/_now
sed -n 's/^.*\(ds:[^ ]* \).*$/\1/p' /proc/drbd >> /etc/ha.d/_now
#ps -o uid,pid,args -e | sed -n 's/^ *0 \(.*[h]eartbeat.*\)$/\1/p' | LANG=C sort >> /etc/ha.d/_now
[ -e /proc/net/bonding/bond0 ] && cat /proc/net/bonding/bond0 >> /etc/ha.d/_now
[ -e /proc/net/bonding/bond1 ] && cat /proc/net/bonding/bond1 >> /etc/ha.d/_now
diff /etc/ha.d/_record /etc/ha.d/_now
EOF
chmod 755 /etc/ha.d/diff || $Error

cat << 'EOF' | tee /etc/ha.d/destroy || $Error
#!/bin/bash
/etc/init.d/heartbeat stop
rm -f $(find /var/lib/pengine/) $(find /var/lib/heartbeat/crm/) /var/lib/heartbeat/hb_generation 2> /dev/null
> /var/log/ha-log
EOF
chmod 755 /etc/ha.d/destroy || $Error

cat << 'EOF' | tee /etc/ha.d/load || $Error
#!/bin/bash
crm configure load update $1
EOF
chmod 755 /etc/ha.d/load || $Error

cat << 'EOF' | tee /etc/ha.d/drbd_slave_recover || $Error
#!/bin/bash
if grep -q ds:UpToDate/UpToDate /proc/drbd; then
  echo There is no problem.
  exit 0
fi
. /etc/ha.d/_param_cluster || exit 1
if ip addr show | grep -q " $HA_VIP/26"; then
  echo This node is active.
  exit 1
fi
if ! rpcinfo $HA_VIP; then
  echo There is no active server.
  exit 1
fi
/etc/init.d/heartbeat stop || :
echo yes | drbdadm wipe-md r0 || exit 1
echo yes | drbdadm create-md r0 || exit 1
/etc/init.d/heartbeat start
echo
echo The processing is continued even if you stop this program ($0).
echo
date
while ! grep -q sync /proc/drbd; do sleep 5;date; done
while grep sync /proc/drbd; do sleep 10;date; done
EOF
chmod 755 /etc/ha.d/drbd_slave_recover || $Error

cat << EOF | tee /etc/ha.d/_param_cluster || $Error
. /etc/ha.d/param_cluster
CENTOS_VER=$CENTOS_VER
EOF
cat << 'EOF' | tee -a /etc/ha.d/_param_cluster || $Error
HA_NETWORK_123=$(echo $HA_VIP | awk -F. '{print $1 "." $2 "." $3}')
if [ "$HA_NETWORK_123" != "$(echo $HA1_IP | awk -F. '{print $1 "." $2 "." $3}')" ]; then
  echo "Error: Network Configuration"
  exit 1
fi
if [ "$HA_NETWORK_123" != "$(echo $HA2_IP | awk -F. '{print $1 "." $2 "." $3}')" ]; then
  echo "Error: Network Configuration"
  exit 1
fi
HA_NETWORK_4=$(($(echo $HA_VIP | awk -F. '{print $4}') & -64))
if [ "$HA_NETWORK_4" != "$(($(echo $HA1_IP | awk -F. '{print $4}') & -64))" ]; then
  echo "Error: Network Configuration"
  exit 1
fi
if [ "$HA_NETWORK_4" != "$(($(echo $HA2_IP | awk -F. '{print $4}') & -64))" ]; then
  echo "Error: Network Configuration"
  exit 1
fi
if [ "$HA_VIP" = "$HA1_IP" -o "$HA_VIP" = "$HA2_IP" -o "$HA1_IP" = "$HA2_IP" ]; then
  echo "Error: Network Configuration"
  exit 1
fi
HA_GATEWAY="$HA_NETWORK_123.$((HA_NETWORK_4+1))"
HA1_HB_IP=192.168.0.$(echo $HA1_IP | awk -F. '{print $4}')
HA2_HB_IP=192.168.0.$(echo $HA2_IP | awk -F. '{print $4}')
HA1_NAME=$HA1_NODE.$HA_DOMAIN
HA2_NAME=$HA2_NODE.$HA_DOMAIN
HA1_HB_NODE=${HA1_NODE}-hb
HA2_HB_NODE=${HA2_NODE}-hb
HA1_HB_NAME=$HA1_HB_NODE.$HA_DOMAIN
HA2_HB_NAME=$HA2_HB_NODE.$HA_DOMAIN
HA_NAME=$HA_NODE.$HA_DOMAIN
HA_GATEWAY_NAME=$HA_GATEWAY_NODE.$HA_DOMAIN
[ -e /proc/net/bonding ] && NIC0=bond0 || NIC0=eth0
[ -e /proc/net/bonding ] && NIC1=bond1 || NIC1=eth1
[ "$(uname -n)" = "$HA1_NAME" ] && PRIV_IP=$HA1_IP || PRIV_IP=$HA2_IP
[ "$(uname -n)" = "$HA1_NAME" ] && PUB_IP=$HA1_HB_IP || PUB_IP=$HA2_HB_IP
[ "$(uname -n)" = "$HA1_NAME" ] && PEER_PRIV_IP=$HA2_IP || PEER_PRIV_IP=$HA1_IP
[ "$(uname -n)" = "$HA1_NAME" ] && PEER_PUB_IP=$HA2_HB_IP || PEER_PUB_IP=$HA1_HB_IP
[ "$SSH_CLIENTS" = "10.0.0.0/8" ] || SSH_CLIENTS="$SSH_CLIENTS,$HA1_IP,$HA2_IP,$HA_VIP"
HA_DEV1=xvdc
if [ ! -d /proc/xen/ ]; then
  lsmod | grep -q ^aacraid && HA_DEV1=sdc || HA_DEV1=sda
fi
:
EOF

cat << 'EOF_NFSSERVER_FOR_BACKUP' | tee /etc/ha.d/mk_nfsserver_for_backup || $Error
#!/bin/bash

NFS_EXPORT_POINT=/backup
date
echo
if grep UpToDate /proc/drbd 2> /dev/null; then
  echo "This server is already setuped."
  exit 1
fi
if [ "$1" = "MASTER" ]; then
  INIT_MODE=MASTER
elif [ "$1" = "SLAVE" ]; then
  INIT_MODE=SLAVE
elif [ "$1" ]; then
  if [ "$(id)" = "$(id root)" ]; then
    echo; echo "You have no authority."
    exit 1
  fi
  if ! sudo date; then
    echo; echo "You have no authority."
    exit 1
  fi
  if ! ping -c 1 $1; then
    if ! ping -c 1 $1; then
      if ! ping -c 1 $1; then
        echo; echo "No Active node: $1"
        exit 1
      fi
    fi
  fi
  if ip addr show | grep -q " $1/"; then
    echo "This host is Active."
    exit 1
  fi
  if ! rpcinfo -T tcp $1; then
    exit 1
  fi
  if ! ssh -o StrictHostKeyChecking=no -t $1 "stty -onlcr && sudo cat /root/ha_param.tgz" | sudo tee /root/ha_param.tgz > /dev/null; then
    exit 1
  fi
  sudo tar xzvf /root/ha_param.tgz -C / || exit 1
  sudo /etc/init.d/sshd restart || exit 1
  . /etc/ha.d/_param_cluster
  if [ "$(uname -n)" != "$HA1_NAME" -a "$(uname -n)" != "$HA2_NAME" ];then
    echo "Please check hostname."
    exit 1
  fi
  if ! sudo vgdisplay | grep ' vg0$'; then
    echo No vg0 volume group.
    exit 1
  fi
  sudo nohup $0 SLAVE &
  echo && echo "Please log in to this server ($PRIV_IP) again and check log: nohup.out"
  exit 0
else
  if [ "$(id)" = "$(id root)" ]; then
    echo; echo "You have no authority."
    exit 1
  fi
  if ! sudo date; then
    echo; echo "You have no authority."
    exit 1
  fi
  . /etc/ha.d/_param_cluster
  if [ $? -ne 0 ]; then
    echo; echo "You have not edited /etc/ha.d/param_cluster yet."
    exit 1
  fi
  if [ ! "$HA1_NAME" ]; then
    echo; echo "You have not edited /etc/ha.d/param_cluster yet."
    exit 1
  fi
  if [ ! "$HA2_NAME" ]; then
    echo; echo "You have not edited /etc/ha.d/param_cluster yet."
    exit 1
  fi
  if [ ! "$HA1_IP" ]; then
    echo; echo "You have not edited /etc/ha.d/param_cluster yet."
    exit 1
  fi
  if [ ! "$HA2_IP" ]; then
    echo; echo "You have not edited /etc/ha.d/param_cluster yet."
    exit 1
  fi
  if [ ! "$HA_NAME" ]; then
    echo; echo "You have not edited /etc/ha.d/param_cluster yet."
    exit 1
  fi
  if [ ! "$HA_VIP" ]; then
    echo; echo "You have not edited /etc/ha.d/param_cluster yet."
    exit 1
  fi
  if [ ! "$HA_GATEWAY_NAME" ]; then
    echo; echo "You have not edited /etc/ha.d/param_cluster yet."
    exit 1
  fi
  if [ ! "$HA1_HB_NAME" ]; then
    echo; echo "You have not edited /etc/ha.d/param_cluster yet."
    exit 1
  fi
  if [ ! "$HA2_HB_NAME" ]; then
    echo; echo "You have not edited /etc/ha.d/param_cluster yet."
    exit 1
  fi
  if [ ! "$HA1_HB_IP" ]; then
    echo; echo "You have not edited /etc/ha.d/param_cluster yet."
    exit 1
  fi
  if [ ! "$HA2_HB_IP" ]; then
    echo; echo "You have not edited /etc/ha.d/param_cluster yet."
    exit 1
  fi
  if [ ! "$DRBD_SIZE" ]; then
    echo; echo "You have not edited /etc/ha.d/param_cluster yet."
    exit 1
  fi
  if [ ! "$DRBD_PASSWORD" ]; then
    echo; echo "You have not edited /etc/ha.d/param_cluster yet."
    exit 1
  fi
  if [ ! "$VIP_CLIENTS" ]; then
    echo; echo "You have not edited /etc/ha.d/param_cluster yet."
    exit 1
  fi
  if [ ! "$NFS_EXPORT_POINT" ]; then
    echo; echo "You have not edited /etc/ha.d/param_cluster yet."
    exit 1
  fi
  if [ "$(uname -n)" != "$HA1_NAME" ];then
    echo "Please check hostname."
    exit 1
  fi
  if ! sudo vgdisplay | grep ' vg0$'; then
    echo No vg0 volume group.
    exit 1
  fi
  sudo nohup $0 MASTER &
  echo && echo "Please log in to this server ($HA1_IP) again and check log: nohup.out"
  exit 0
fi

if [ "$(id)" != "$(id root)" ]; then
  echo; echo "You have no authority."
  exit 1
fi
. /etc/ha.d/_param_cluster
if [ $? -ne 0 ]; then
  echo; echo "You have not edited /etc/ha.d/param_cluster yet."
  exit 1
fi

set -x
if ! lvdisplay | grep /dev/vg0/drbd0; then
  lvcreate --name drbd0 --size $DRBD_SIZE vg0 || exit 1
fi

sed -i -e 's/^RPCIDMAPDARGS=.*$/RPCIDMAPDARGS="-S"/' /etc/sysconfig/nfs
chmod -x /sbin/mount.nfs
chmod -x /sbin/mount.nfs4

sed -i -e "s/^IPADDR=.*\$/IPADDR=$PRIV_IP/" /etc/sysconfig/network-scripts/ifcfg-$NIC0
sed -i -e "s/^IPADDR=.*\$/IPADDR=$PUB_IP/" /etc/sysconfig/network-scripts/ifcfg-$NIC1
sed -i -e '/^GATEWAY=/d' /etc/sysconfig/network-scripts/ifcfg-$NIC0
sed -i -e '/^GATEWAY=/d' /etc/sysconfig/network-scripts/ifcfg-$NIC1

sed -i -e "s/^GATEWAY=.*\$/GATEWAY=$HA_GATEWAY/" /etc/sysconfig/network
rm -f /etc/sysconfig/network-scripts/route-$NIC0

sed -i -e "s/ip=[0-9.]* /ip=$PRIV_IP /" /boot/grub/grub.conf
sed -i -e "s/gateway=[0-9.]* /gateway=$HA_GATEWAY /" /boot/grub/grub.conf

cat << EOF | tee /etc/hosts
127.0.0.1^localhost.localdomain localhost
$HA_GATEWAY^$HA_GATEWAY_NAME $HA_GATEWAY_NODE
$HA_VIP^$HA_NAME $HA_NODE
$HA1_IP^$HA1_NAME $HA1_NODE
$HA2_IP^$HA2_NAME $HA2_NODE
$HA1_HB_IP^$HA1_HB_NAME $HA1_HB_NODE
$HA2_HB_IP^$HA2_HB_NAME $HA2_HB_NODE
EOF
sed -i -e 's/\^/\t/g' /etc/hosts

/etc/init.d/network restart

cat << EOF | tee /etc/sysconfig/iptables
*filter
:INPUT   ACCEPT [0:0]
:FORWARD ACCEPT [0:0]
:OUTPUT  ACCEPT [0:0]
-A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
-A INPUT -i lo -j ACCEPT
########## Public VLAN (& Private VLAN) ##########
-A INPUT -s $HA1_HB_IP,$HA2_HB_IP -j ACCEPT
-A INPUT -i eth1  -j DROP
-A INPUT -i eth3  -j DROP
-A INPUT -i bond1 -j DROP
########## Private VLAN ##########
-A INPUT -s $HA1_IP,$HA2_IP,$HA_VIP -j ACCEPT
-A INPUT -p tcp --dport 2049  -m tcp -m state --state NEW -s $VIP_CLIENTS -d $HA_VIP -j ACCEPT
-A INPUT -p udp --dport 2049  -m udp -m state --state NEW -s $VIP_CLIENTS -d $HA_VIP -j ACCEPT
-A INPUT -p tcp --dport 111   -m tcp -m state --state NEW -s $VIP_CLIENTS -d $HA_VIP -j ACCEPT
-A INPUT -p udp --dport 111   -m udp -m state --state NEW -s $VIP_CLIENTS -d $HA_VIP -j ACCEPT
-A INPUT -p tcp --dport 662   -m tcp -m state --state NEW -s $VIP_CLIENTS -d $HA_VIP -j ACCEPT
-A INPUT -p udp --dport 662   -m udp -m state --state NEW -s $VIP_CLIENTS -d $HA_VIP -j ACCEPT
-A INPUT -p tcp --dport 875   -m tcp -m state --state NEW -s $VIP_CLIENTS -d $HA_VIP -j ACCEPT
-A INPUT -p udp --dport 875   -m udp -m state --state NEW -s $VIP_CLIENTS -d $HA_VIP -j ACCEPT
-A INPUT -p tcp --dport 892   -m tcp -m state --state NEW -s $VIP_CLIENTS -d $HA_VIP -j ACCEPT
-A INPUT -p udp --dport 892   -m udp -m state --state NEW -s $VIP_CLIENTS -d $HA_VIP -j ACCEPT
-A INPUT -p tcp --dport 32803 -m tcp -m state --state NEW -s $VIP_CLIENTS -d $HA_VIP -j ACCEPT
-A INPUT -p udp --dport 32769 -m udp -m state --state NEW -s $VIP_CLIENTS -d $HA_VIP -j ACCEPT
-A INPUT -p tcp --dport 22    -m tcp -m state --state NEW -s $SSH_CLIENTS -j ACCEPT
-A INPUT -p tcp --dport 3001  -m tcp -m state --state NEW -s $SSH_CLIENTS -j ACCEPT
-A INPUT -p tcp --dport 3003  -m tcp -m state --state NEW -s $SSH_CLIENTS -j ACCEPT
-A INPUT -p icmp -s 10.0.0.0/8 -j ACCEPT
#-A INPUT -j LOG --log-prefix "ip_tables: " --log-level=debug
-A INPUT -j REJECT --reject-with icmp-host-prohibited
########## FORWARD ##########
-A FORWARD -j REJECT --reject-with icmp-host-prohibited
COMMIT
EOF
if ! ifconfig bond0 2> /dev/null; then
  sed -i -e '/bond0/ s/^/#/' /etc/sysconfig/iptables
  sed -i -e '/bond1/ s/^/#/' /etc/sysconfig/iptables
  sed -i -e '/eth2/  s/^/#/' /etc/sysconfig/iptables
  sed -i -e '/eth3/  s/^/#/' /etc/sysconfig/iptables
fi
/etc/init.d/iptables restart

if ! grep -q '^## DRBD ##$' /etc/sysctl.conf; then
  cat << 'EOF' | tee -a /etc/sysctl.conf

## DRBD ##
net.core.wmem_max = 16777216
net.core.rmem_max = 16777216
net.core.wmem_default = 16777216
net.core.rmem_default = 16777216
net.core.netdev_max_backlog = 250000
net.core.optmem_max = 16777216
net.ipv4.tcp_wmem = 4096 65536 16777216
net.ipv4.tcp_rmem = 4096 87380 16777216
net.ipv4.tcp_window_scaling = 1
net.ipv4.tcp_timestamps = 0
net.ipv4.tcp_sack = 0
net.ipv4.tcp_no_metrics_save = 1
kernel.panic = 0
kernel.panic_on_oops = 1
vm.swappiness = 0
EOF
  sysctl -p
fi

cat << EOF | tee /etc/drbd.d/global_common.conf
global {
  usage-count no;
}
common {
  handlers {
    local-io-error "/usr/lib/drbd/notify-io-error.sh; /usr/lib/drbd/notify-emergency-shutdown.sh; echo 1 > /proc/sys/kernel/sysrq; echo o > /proc/sysrq-trigger ; halt -f";
    fence-peer "/usr/lib/drbd/crm-fence-peer.sh";
    after-resync-target /usr/lib/drbd/crm-unfence-peer.sh;
  }
  startup {
#wfc#    wfc-timeout 10;
#wfc#    degr-wfc-timeout 10;
#wfc#    outdated-wfc-timeout 10;
  }
  disk {
    on-io-error detach;
    fencing resource-only;
    al-extents 6433;
    c-plan-ahead 20;
    c-delay-target 100;
    c-fill-target 0;
    c-max-rate 100M;
    c-min-rate 1M;
  }
  net {
    protocol C;
    max-buffers 128k;
    sndbuf-size 0;
    rcvbuf-size 0;
    cram-hmac-alg sha1;
    shared-secret "$DRBD_PASSWORD";
    congestion-fill 100M;
    congestion-extents 2000;
    csums-alg md5;
    verify-alg md5;
    use-rle;
  }
}
EOF

cat << EOF | tee /etc/drbd.d/r0.res
resource r0 {
  volume 0 {
    device /dev/drbd0;
    disk /dev/vg0/drbd0;
    meta-disk internal;
  }
  on $HA1_NAME {
    address $HA1_HB_IP:7788;
  }
  on $HA2_NAME {
    address $HA2_HB_IP:7788;
  }
}
EOF

if ! grep /var/log/ha-log /etc/rsyslog.conf; then
  sed -i -e 's%/var/log/local2.log%/var/log/ha-log%' /etc/rsyslog.conf
  mv /var/log/local2.log /var/log/ha-log 2> /dev/null || :
  /etc/init.d/rsyslog restart
fi

cat << 'EOF' | tee /etc/logrotate.d/heartbeat

EOF

sed -i -e 's%/var/log/local2.log%/var/log/ha-log%' /etc/logrotate.d/syslog

cat << 'EOF' | tee /etc/ha.d/authkeys
auth 1
1 crc
EOF
chmod 600 /etc/ha.d/authkeys
cat << EOF | tee /etc/ha.d/ha.cf
crm yes
debug 0
logfacility local2
keepalive 2
warntime 7
deadtime 10
initdead 48
udpport 694
ucast $NIC0 $PEER_PRIV_IP
ucast $NIC1 $PEER_PUB_IP
node $HA1_NAME
node $HA2_NAME
uuidfrom nodename
autojoin none
respawn root /usr/lib64/heartbeat/ifcheckd
EOF

VIP_CLIENTS=$(echo $VIP_CLIENTS | tr , " ")
P_VIP=p_vip_$(echo $HA_VIP | tr . _)

cat << EOF | tee /etc/ha.d/crm_nfsserver_for_backup
primitive p_drbd_r0 ocf:linbit:drbd \\
  params drbd_resource="r0" \\
  op start   interval="0" timeout="240s" \\
  op monitor interval="31s" role="Master" timeout="20s" \\
  op monitor interval="29s" role="Slave"  timeout="20s" \\
  op notify  interval="0" timeout="90s" \\
  op stop    interval="0" timeout="120s" \\
  op promote interval="0" timeout="90s" \\
  op demote  interval="0" timeout="90s"
primitive p_vipcheck ocf:heartbeat:VIPcheck \\
  params target_ip="$HA_VIP" count="1" wait="10"  \\
  op start interval="0" timeout="90s" start_delay="4s" \\
  op stop  interval="0" timeout="60s"
primitive $P_VIP ocf:heartbeat:IPaddr2 \\
  params ip=$HA_VIP cidr_netmask=26 \\
  op start   interval="0"   timeout="20" \\
  op monitor interval="30s" timeout="20" \\
  op stop    interval="0"   timeout="20"
primitive p_vip ocf:heartbeat:IPsrcaddr \\
  params ipaddress=$HA_VIP \\
  op monitor interval="50s" timeout="30"
primitive p_fs_export ocf:heartbeat:Filesystem \\
  params device=/dev/drbd0 directory=/export fstype=ext4 run_fsck="no" \\
  op start   interval="0"   timeout="60s" \\
  op monitor interval="10s" timeout="40s" \\
  op stop    interval="0"   timeout="60s"
primitive p_fs_nfs3 ocf:heartbeat:Filesystem \\
  params device=/export$NFS_EXPORT_POINT directory=$NFS_EXPORT_POINT fstype=none options="bind" \\
  op start   interval="0"   timeout="60s" \\
  op monitor interval="10s" timeout="40s" \\
  op stop    interval="0"   timeout="60s"
primitive p_ping ocf:pacemaker:ping \\
  params name="p_ping" host_list="$HA_GATEWAY" multiplier="1000" dampen="5s" \\
  op start   interval="0"   timeout="60s" \\
  op monitor interval="30s" timeout="60s" \\
  op stop    interval="0"   timeout="20s"
primitive p_diskd_root ocf:pacemaker:diskd \\
        params name="p_diskd_root" write_dir="/tmp" interval="10" \\
        op start   interval="0"   timeout="60s" \\
        op monitor interval="10s" timeout="60s" \\
        op stop    interval="0"   timeout="60s"
primitive p_diskd_share1 ocf:pacemaker:diskd \\
        params name="p_diskd_share1" device="/dev/$HA_DEV1" interval="10" \\
        op start   interval="0"   timeout="60s" \\
        op monitor interval="10s" timeout="60s" \\
        op stop    interval="0"   timeout="60s"
primitive p_rpcbind lsb:rpcbind \\
  op monitor interval="30s"
primitive p_nfslock lsb:nfslock \\
  op monitor interval="30s"
primitive p_nfsserver lsb:nfs \\
  op monitor interval="30s"
primitive p_exp_root ocf:heartbeat:exportfs \\
  params fsid="0" directory="/export" \\
  options="rw,sync,crossmnt" \\
  clientspec="$VIP_CLIENTS" wait_for_leasetime_on_stop="false" \\
  op start interval="0" timeout="240s" \\
  op stop  interval="0" timeout="100s"
primitive p_exp_backup ocf:heartbeat:exportfs \\
  params fsid="1" directory="/export$NFS_EXPORT_POINT" \\
  options="rw,sync,mountpoint" \\
  clientspec="$VIP_CLIENTS" wait_for_leasetime_on_stop="false" \\
  op start   interval="0"   timeout="240s" \\
  op monitor interval="30s" \\
  op stop    interval="0"   timeout="100s" \\
  meta is-managed="true"
primitive p_exp_nfs3 ocf:heartbeat:exportfs \\
  params fsid="2" directory="$NFS_EXPORT_POINT" \\
  options="rw,sync" \\
  clientspec="$VIP_CLIENTS" wait_for_leasetime_on_stop="false" \\
  op start   interval="0"   timeout="240s" \\
  op monitor interval="30s" \\
  op stop    interval="0"   timeout="100s" \\
  meta is-managed="true"
group g_nfs p_vipcheck p_fs_export p_fs_nfs3 p_rpcbind p_nfslock p_nfsserver p_exp_root p_exp_backup p_exp_nfs3 $P_VIP p_vip
ms ms_drbd_r0 p_drbd_r0 \\
  meta master-max="1" master-node-max="1" clone-max="2" \\
  clone-node-max="1" notify="true" target-role="Started" \\
  is-managed="true"
clone cl_ping p_ping
clone cl_diskd_share1 p_diskd_share1
clone cl_diskd_root p_diskd_root
location lc_nfs g_nfs 100: $HA1_NAME
location lc_ping_disk g_nfs \\
  rule \$id="lc_ping_disk-rule" 100: #uname eq $HA1_NAME \\
  rule \$id="lc_ping_disk-rule-1" -inf: defined p_ping and p_ping lt 100 \\
  rule \$id="lc_ping_disk-rule-2" -inf: defined p_diskd_root and p_diskd_root eq ERROR \\
  rule \$id="lc_ping_disk-rule-3" -inf: defined p_diskd_share1 and p_diskd_share1 eq ERROR
colocation cl_nfs inf: g_nfs ms_drbd_r0:Master
order ord_nfs 0: ms_drbd_r0:promote g_nfs:start
property stonith-enabled="false"
property no-quorum-policy="ignore"
property pe-error-series-max="100"
property pe-warn-series-max="100"
property pe-input-series-max="100"
rsc_defaults migration-threshold="2"
rsc_defaults resource-stickiness="200"
EOF

if [ "$INIT_MODE" = "MASTER" ]; then
  echo yes | drbdadm wipe-md r0 || exit 1
  echo yes | drbdadm create-md r0 || exit 1
  sed -i -e '/wfc-timeout/ s/^#wfc#//' /etc/drbd.d/global_common.conf || exit 1
  /etc/init.d/drbd start || exit 1
  sed -i -e '/wfc-timeout/ s/^\([^#]\)/#wfc#\1/' /etc/drbd.d/global_common.conf || exit 1
  drbdadm primary --force all || exit 1
  mkfs.ext4 /dev/drbd0 || exit 1
  tune2fs -c 0 -i 0 /dev/drbd0 || exit 1
  mkdir /export || exit 1
  mkdir -p $NFS_EXPORT_POINT || exit 1
  mkdir -p /var/lib/rpc_pipefs/ || exit 1
  mount /dev/drbd0 /export || exit 1
  /etc/init.d/rpcbind start || exit 1
  /etc/init.d/nfslock start || exit 1
  /etc/init.d/nfs start || exit 1
  /etc/init.d/nfs stop || exit 1
  /etc/init.d/nfslock stop || exit 1
  /etc/init.d/rpcbind stop || exit 1
  chkconfig --del netfs || exit 1
  chkconfig --del nfslock || exit 1
  chkconfig --del rpcbind || exit 1
  umount /var/lib/nfs/rpc_pipefs/ || exit 1
  mv /var/lib/nfs /export/ || exit 1
  ln -s /export/nfs /var/lib/nfs || exit 1
  rmdir /export/nfs/rpc_pipefs/ || exit 1
  ln -s /var/lib/rpc_pipefs /export/nfs/rpc_pipefs || exit 1
  mkdir -p /export$NFS_EXPORT_POINT/system || exit 1
  chmod 700 /export$NFS_EXPORT_POINT/system || exit 1
  chown -R nfsnobody:nfsnobody /export$NFS_EXPORT_POINT || exit 1
  umount /export/ || exit 1
  drbdadm secondary all || exit 1
  /etc/init.d/drbd stop || exit 1
  rm -f $(find /var/lib/pengine/) $(find /var/lib/heartbeat/crm/) /var/lib/heartbeat/hb_generation 2> /dev/null
  /etc/init.d/heartbeat start || exit 1
  while ! crm_mon -1rfA | grep "Online: \[ $(uname -n) \]"; do sleep 5; done
  crm configure load update /etc/ha.d/crm_nfsserver_for_backup || exit 1
  while ! crm_mon -1rfA | grep IPaddr2 | grep Started; do sleep 5; done
  crm_mon -1frA
  mkdir -p $NFS_EXPORT_POINT/ks || exit 1
  cat << EOF | tee $NFS_EXPORT_POINT/ks/backup_boot_root.cfg
install
text
reboot
nfs --server=$HA_VIP --dir=/backup/co6.5
lang en_US.UTF-8
keyboard jp106
timezone --utc Asia/Tokyo
authconfig --enableshadow --passalgo=sha512
rootpw password
bootloader --location=none
part / --recommended
%packages
@Core
%end
EOF
  cat << 'EOF' | tee -a $NFS_EXPORT_POINT/ks/backup_boot_root.cfg
%pre
[ -d /proc/xen/ ] || exec < /dev/tty3 > /dev/tty3 2>&1
[ -d /proc/xen/ ] || /usr/bin/chvt 3
[ -d /proc/xen/ ] || set -x
[ -d /proc/xen/ ] && DEV=xvda || DEV=sda
ifconfig eth1 down
[ -d /proc/xen/ ] || ifconfig eth3 down
for i in $(cat /proc/cmdline)
do
  echo $i | grep -q = || continue
  echo $i | grep -q -v ^= || continue
  eval $i
  echo $i
done
mkdir /mnt/sysimage
mount /dev/${DEV}2 /mnt/sysimage
mount /dev/${DEV}1 /mnt/sysimage/boot
[ -d /proc/xen/ ] && sed -i -e '/^default=/d' -e 's/^##rescue##default=/default=/' -e '/vmlinuz / s%^.*$%\tkernel /vmlinuz rescue repo=http://mirrors.service.networklayer.com/centos/6/os/x86_64/ lang=en_US keymap=jp106 selinux=0 sshd=1 nomount ksdevice=eth0 ip='"$(ifconfig eth0 | grep inet | awk '{print $2}' | awk -F: '{print $2}') netmask=255.255.255.192 gateway=$(if route -n | grep -q '^10\.0\.0\.0'; then route -n | grep '^10\.0\.0\.0'; else route -n | grep '^0\.0\.0\.0'; fi | awk '{print $2}') dns=10.0.80.11%" /mnt/sysimage/boot/grub/grub.conf
mkdir /backup
mount -t nfs $(echo $ks | awk -F: '{print $2}'):/backup /backup
if [ ! -d /backup/system ]; then
  umount /backup
  mount -o ro,remount /dev/${DEV}2 /mnt/sysimage
  mount -o ro,remount /dev/${DEV}1 /mnt/sysimage/boot
  reboot
fi
. /mnt/sysimage/etc/sysconfig/network
DATETIME=$(TZ=JST-9 date +%Y%m%d%H%M)
mkdir -p /backup/system/$HOSTNAME/$DATETIME
cd /mnt/sysimage
tar czf /backup/system/$HOSTNAME/$DATETIME/boot.tgz boot > /dev/null 2>&1
umount /mnt/sysimage/boot
tar czf /backup/system/$HOSTNAME/$DATETIME/root.tgz . > /dev/null 2>&1
## other partition ##
mount /dev/${DEV}1 /mnt/sysimage/boot
[ -d /proc/xen/ ] && sed -i -e "s/backup=[0-9]* /backup=$DATETIME /" /boot/grub/grub.conf
[ -d /proc/xen/ ] && reboot
umount /backup
mount -t proc /proc /mnt/sysimage/proc
chroot /mnt/sysimage /usr/local/sbin/reboot_quick noreboot backup=$DATETIME
mount -o ro,remount /dev/${DEV}2 /mnt/sysimage
mount -o ro,remount /dev/${DEV}1 /mnt/sysimage/boot
chroot /mnt/sysimage /sbin/kexec -e
[ -d /proc/xen/ ] || /usr/bin/chvt 1
reboot
%end
%post
%end
EOF
  mkdir -p $NFS_EXPORT_POINT/co$CENTOS_VER/images || exit 1
  wget -q http://mirrors.service.networklayer.com/centos/$CENTOS_VER/isos/x86_64/CentOS-$CENTOS_VER-x86_64-minimal.iso -O $NFS_EXPORT_POINT/co$CENTOS_VER/CentOS-$CENTOS_VER-x86_64-minimal.iso || exit 1
  mount -o loop $NFS_EXPORT_POINT/co$CENTOS_VER/CentOS-$CENTOS_VER-x86_64-minimal.iso /mnt || exit 1
  cp /mnt/images/{install.img,updates.img} $NFS_EXPORT_POINT/co$CENTOS_VER/images/ || exit 1
  umount /mnt || exit 1
  cd / || exit 1
  if [ ! -e /root/.ssh/id_rsa ]; then
    ssh-keygen -q -f /root/.ssh/id_rsa -N "" || exit 1
    mv -f /root/.ssh/id_rsa.pub /root/.ssh/authorized_keys || exit 1
  fi
  sed -i -e 's/^PermitRootLogin no$/#PermitRootLogin no/' -e 's/^#PermitRootLogin without-password$/PermitRootLogin without-password/' /etc/ssh/sshd_config || exit 1
  tar czvf /root/ha_param.tgz etc/ssh etc/ha.d/param_cluster etc/ha.d/_param_cluster root/.ssh/id_rsa root/.ssh/authorized_keys || exit 1
  /etc/init.d/sshd restart || exit 1
  echo; echo "The setup of the master server was completed. Please set up the slave server."
elif [ "$INIT_MODE" = "SLAVE" ]; then
  echo yes | drbdadm wipe-md r0 || exit 1
  echo yes | drbdadm create-md r0 || exit 1
  mkdir /export || exit 1
  mkdir -p $NFS_EXPORT_POINT || exit 1
  chkconfig --del netfs || exit 1
  chkconfig --del nfslock || exit 1
  chkconfig --del rpcbind || exit 1
  mkdir -p /var/lib/rpc_pipefs/ || exit 1
  rm -rf /var/lib/nfs || exit 1
  ln -s /export/nfs /var/lib/nfs || exit 1
  sed -i -e '/wfc-timeout/ s/^\([^#]\)/#wfc#\1/' /etc/drbd.d/global_common.conf || exit 1
  rm -f $(find /var/lib/pengine/) $(find /var/lib/heartbeat/crm/) /var/lib/heartbeat/hb_generation 2> /dev/null
  /etc/init.d/heartbeat start || exit 1
  while ! grep -q sync /proc/drbd 2> /dev/null; do date;sleep 5; done
  cat /proc/drbd
  while grep sync /proc/drbd; do date;sleep 60; done
  cat /proc/drbd
  crm_mon -1frA
  /etc/ha.d/record
  echo; echo "The setup of the slave server was completed."
else
  echo; echo "You have not edited /etc/ha.d/param_cluster correctly."
  exit 1
fi
date
EOF_NFSSERVER_FOR_BACKUP
chmod 755 /etc/ha.d/mk_nfsserver_for_backup || $Error

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

if grep -q -v ^# /etc/cron.d/raid-check; then
  sed -i -e 's/^/#/' /etc/cron.d/raid-check || $Error
fi

for i in $(ls /etc/init.d/)
do
  chkconfig --del $i || :
  case $i in
    atd           ) chkconfig --add $i || $Error; chkconfig $i on  || $Error;;
    auditd        ) chkconfig --add $i || $Error; chkconfig $i on  || $Error;;
    crond         ) chkconfig --add $i || $Error; chkconfig $i on  || $Error;;
    httpd24-httpd ) chkconfig --add $i || $Error; chkconfig $i on  || $Error;;
    iptables      ) chkconfig --add $i || $Error; chkconfig $i on  || $Error;;
    irqbalance    ) chkconfig --add $i || $Error; chkconfig $i on  || $Error;;
    munin-node    ) chkconfig --add $i || $Error; chkconfig $i on  || $Error;;
    network       ) chkconfig --add $i || $Error; chkconfig $i on  || $Error;;
    ntop          ) chkconfig --add $i || $Error; chkconfig $i on  || $Error;;
    postfix       ) chkconfig --add $i || $Error; chkconfig $i on  || $Error;;
    psacct        ) chkconfig --add $i || $Error; chkconfig $i on  || $Error;;
    rsyslog       ) chkconfig --add $i || $Error; chkconfig $i on  || $Error;;
    sshd          ) chkconfig --add $i || $Error; chkconfig $i on  || $Error;;
    sysstat       ) chkconfig --add $i || $Error; chkconfig $i on  || $Error;;
    udev-post     ) chkconfig --add $i || $Error; chkconfig $i on  || $Error;;
    vnstat        ) chkconfig --add $i || $Error; chkconfig $i on  || $Error;;
    watchdog      ) chkconfig --add $i || $Error; chkconfig $i on  || $Error;;

    netfs         ) chkconfig --add $i || $Error; chkconfig $i off || $Error;;
    nfslock       ) chkconfig --add $i || $Error; chkconfig $i off || $Error;;
    rpcbind       ) chkconfig --add $i || $Error; chkconfig $i off || $Error;;
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

echo $MY_ROOT_PW | passwd --stdin root || $Error

/usr/local/sbin/reboot_quick || $Error
