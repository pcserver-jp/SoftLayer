#!/bin/bash

MY_ROOT_PW=
MY_SL_ADMIN=sl-admin
MY_SL_ADMIN_INIT_PW=sl-admin
MY_SL_ADMIN_ID=65501
WHEEL_SUDO_NOPASSWD=yes

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
  [ -x /root/post_install.* ] && mv /root/post_install.* /root/post_install.sh 2> /dev/null
fi
exec > /root/post_install.log || $Error
exec 2>&1 || $Error
set -x || $Error

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
-A INPUT -p tcp  --dport 22  -m tcp -m state --state NEW -s 10.0.0.0/8 -j ACCEPT
-A INPUT -p icmp                                         -s 10.0.0.0/8 -j ACCEPT
#-A INPUT -j LOG --log-prefix "IPTABLES_REJECT_PRIVATE : " --log-level=info
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

ifconfig || $Error
route -n || $Error
netstat -anp || $Error
echo --------------------------------------------------------------------------------
for i in eth0 eth1 eth2 eth3 bond0 bond1
do
  ifconfig $i > /dev/null 2>&1 || break
  for j in "" --show-pause --show-coalesce --show-ring --driver --register-dump --eeprom-dump --show-features --show-permaddr --statistics --show-nfc --get-dump --show-time-stamping --show-rxfh-indir --show-channels --dump-module-eeprom --show-priv-flags --show-eee
  do
    echo --------------------------------------------------------------------------------
    ethtool $j $i 2> /dev/null
  done;
done
echo --------------------------------------------------------------------------------
[ -e /proc/net/bonding/bond0 ] && cat /proc/net/bonding/bond0
echo --------------------------------------------------------------------------------
[ -e /proc/net/bonding/bond1 ] && cat /proc/net/bonding/bond1
echo --------------------------------------------------------------------------------
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
if [ -e /etc/sysconfig/network-scripts/ifcfg-eth0  ]; then
  cat /etc/sysconfig/network-scripts/ifcfg-eth0 || $Error
  sed -i -e '/^NM_CONTROLLED.*$/d' /etc/sysconfig/network-scripts/ifcfg-eth0 || $Error
  echo 'NM_CONTROLLED=no' | tee -a /etc/sysconfig/network-scripts/ifcfg-eth0 || $Error
fi
if [ -e /etc/sysconfig/network-scripts/ifcfg-eth1  ]; then
  cat /etc/sysconfig/network-scripts/ifcfg-eth1 || $Error
  sed -i -e '/^NM_CONTROLLED.*$/d' /etc/sysconfig/network-scripts/ifcfg-eth1 || $Error
  echo 'NM_CONTROLLED=no' | tee -a /etc/sysconfig/network-scripts/ifcfg-eth1 || $Error
fi
if [ -e /etc/sysconfig/network-scripts/ifcfg-eth2  ]; then
  cat /etc/sysconfig/network-scripts/ifcfg-eth2 || $Error
  sed -i -e '/^NM_CONTROLLED.*$/d' /etc/sysconfig/network-scripts/ifcfg-eth2 || $Error
  echo 'NM_CONTROLLED=no' | tee -a /etc/sysconfig/network-scripts/ifcfg-eth2 || $Error
fi
if [ -e /etc/sysconfig/network-scripts/ifcfg-eth3  ]; then
  cat /etc/sysconfig/network-scripts/ifcfg-eth3 || $Error
  sed -i -e '/^NM_CONTROLLED.*$/d' /etc/sysconfig/network-scripts/ifcfg-eth3 || $Error
  echo 'NM_CONTROLLED=no' | tee -a /etc/sysconfig/network-scripts/ifcfg-eth3 || $Error
fi
if [ -e /etc/sysconfig/network-scripts/ifcfg-bond0 ]; then
  cat /etc/sysconfig/network-scripts/ifcfg-bond0 || $Error
  sed -i -e '/^NM_CONTROLLED.*$/d' /etc/sysconfig/network-scripts/ifcfg-bond0 || $Error
  echo 'NM_CONTROLLED=no' | tee -a /etc/sysconfig/network-scripts/ifcfg-bond0 || $Error
fi
if [ -e /etc/sysconfig/network-scripts/ifcfg-bond1 ]; then
  cat /etc/sysconfig/network-scripts/ifcfg-bond1 || $Error
  sed -i -e '/^NM_CONTROLLED.*$/d' /etc/sysconfig/network-scripts/ifcfg-bond1 || $Error
  echo 'NM_CONTROLLED=no' | tee -a /etc/sysconfig/network-scripts/ifcfg-bond1 || $Error
fi
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

if grep -q '^NOZEROCONF' /etc/sysconfig/network; then
  cat /etc/sysconfig/network || $Error
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
  umount /disk{,0} || :
  rmdir /disk{,0} || :
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
resize2fs /dev/sda2
mkswap -L swap -U 299ff4da-8897-405b-ae8e-5648a14fc81e /dev/sdb1
cat << 'EOF_FSTAB' | tee -a /etc/fstab
UUID=299ff4da-8897-405b-ae8e-5648a14fc81e swap  swap    pri=9,defaults  0 0
EOF_FSTAB
swapon -a
rm -f /rescue/once
EOF
    chmod 755 /rescue/once || $Error
    if [ -e /dev/sdc -a ! -e /dev/sdc1 ]; then
      echo Yes | parted /dev/sdc mklabel msdos || :
      dd if=/dev/zero of=/dev/sdc bs=1M count=10 || $Error
      echo Yes | parted /dev/sdc mklabel gpt mkpart primary 1MiB 100% set 1 lvm on || $Error
      pvcreate /dev/sdc1 || $Error
      vgcreate -s 32M vg0 /dev/sdc1 || $Error
      for i in d e f g h i j k l m n o p q r s t u v w x y z
      do
        [ -e /dev/sd$i ] || break
        echo Yes | parted /dev/sd$i mklabel msdos || :
        dd if=/dev/zero of=/dev/sd$i bs=1M count=10 || $Error
        echo Yes | parted /dev/sd$i mklabel gpt mkpart primary 1MiB 100% set 1 lvm on || $Error
        pvcreate /dev/sd${i}1 || $Error
        vgextend vg0 /dev/sd${i}1 || :
      done
    fi
  else
    cat << 'EOF' | tee /rescue/once || $Error
#!/bin/bash
resize2fs /dev/sda2
dd if=/dev/zero of=/.swap bs=1M count=2048
mkswap -f -L swap -U 299ff4da-8897-405b-ae8e-5648a14fc81e /.swap
cat << 'EOF_FSTAB' | tee -a /etc/fstab
/.swap                                    swap  swap    pri=0,defaults  0 0
EOF_FSTAB
swapon -a
rm -f /rescue/once
EOF
    chmod 755 /rescue/once || $Error
    if [ -e /dev/sdb -a ! -e /dev/sdb1 ]; then
      echo Yes | parted /dev/sdb mklabel msdos || :
      dd if=/dev/zero of=/dev/sdb bs=1M count=10 || $Error
      echo Yes | parted /dev/sdb mklabel gpt mkpart primary 1MiB 100% set 1 lvm on || $Error
      pvcreate /dev/sdb1 || $Error
      vgcreate -s 32M vg0 /dev/sdb1 || $Error
      for i in c d e f g h i j k l m n o p q r s t u v w x y z
      do
        [ -e /dev/sd$i ] || break
        echo Yes | parted /dev/sd$i mklabel msdos || :
        dd if=/dev/zero of=/dev/sd$i bs=1M count=10 || $Error
        echo Yes | parted /dev/sd$i mklabel gpt mkpart primary 1MiB 100% set 1 lvm on || $Error
        pvcreate /dev/sd${i}1 || $Error
        vgextend vg0 /dev/sd${i}1 || :
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
mkswap -L swap -U 299ff4da-8897-405b-ae8e-5648a14fc81e /dev/xvdb1
cat << 'EOF_FSTAB' | tee -a /etc/fstab
UUID=299ff4da-8897-405b-ae8e-5648a14fc81e swap  swap    pri=9,defaults  0 0
EOF_FSTAB
swapon -a
rm -f /rescue/once
EOF
  chmod 755 /rescue/once || $Error
fi
if [ -e /dev/xvdc -a ! -e /dev/xvdc1 ]; then
  echo Yes | parted /dev/xvdc mklabel msdos || :
  dd if=/dev/zero of=/dev/xvdc bs=1M count=10 || $Error
  echo Yes | parted /dev/xvdc mklabel gpt mkpart primary 1MiB 100% set 1 lvm on || $Error
  pvcreate /dev/xvdc1 || $Error
  vgcreate -s 32M vg0 /dev/xvdc1 || $Error
  for i in d e f
  do
    [ -e /dev/xvd$i ] || break
    echo Yes | parted /dev/xvd$i mklabel msdos || :
    dd if=/dev/zero of=/dev/xvd$i bs=1M count=10 || $Error
    echo Yes | parted /dev/xvd$i mklabel gpt mkpart primary 1MiB 100% set 1 lvm on || $Error
    pvcreate /dev/xvd${i}1 || $Error
    vgextend vg0 /dev/xvd${i}1 || $Error
  done
fi
blkid

cat /etc/inittab || $Error
echo 'id:3:initdefault:' | tee /etc/inittab || $Error

cat /boot/grub/grub.conf || $Error
if ! grep -q ' selinux=0 ' /boot/grub/grub.conf; then
  wget -O /boot/vmlinuz http://mirrors.service.networklayer.com/centos/6.5/os/x86_64/isolinux/vmlinuz || $Error
  wget -O /boot/initrd.img http://mirrors.service.networklayer.com/centos/6.5/os/x86_64/isolinux/initrd.img || $Error
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
^kernel /vmlinuz rescue repo=http://mirrors.service.networklayer.com/centos/6.5/os/x86_64/ lang=en_US keymap=jp106 selinux=0 biosdevname=0 nomount sshd=1 ksdevice=eth0 ip=$IP0 netmask=255.255.255.192 gateway=$GATEWAY0 dns=$DNS0
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
if [ -d /proc/xen/ ]; then
  sed -i -e 's/^\(default=.*\)$/##rescue##\1\ndefault='"$(($(grep ^title /boot/grub/grub.conf | wc -l)-1))/" -e '/vmlinuz / s%^.*$%\tkernel /vmlinuz lang=en_US keymap=jp106 selinux=0 ksdevice=eth0 ip='"$(ifconfig eth0 | grep inet | awk '{print $2}' | awk -F: '{print $2}') netmask=255.255.255.192 gateway=$(if route -n | grep -q '^10\.0\.0\.0'; then route -n | grep '^10\.0\.0\.0'; else route -n | grep '^0\.0\.0\.0'; fi | awk '{print $2}') dns=$(grep ^nameserver /etc/resolv.conf | head -1 | awk '{print $2}') ks=nfs:$1:/backup/ks/$(uname -n).cfg%" /boot/grub/grub.conf && reboot
else
  kexec -l /boot/vmlinuz --initrd=/boot/initrd.img --command-line="lang=en_US keymap=jp106 selinux=0 ksdevice=eth0 ip=$(ifconfig $(ifconfig bond0 > /dev/null 2>&1 && echo bond0 || echo eth0) | grep inet | awk '{print $2}' | awk -F: '{print $2}') netmask=255.255.255.192 gateway=$(if route -n | grep -q '^10\.0\.0\.0'; then route -n | grep '^10\.0\.0\.0'; else route -n | grep '^0\.0\.0\.0'; fi | awk '{print $2}') dns=$(grep ^nameserver /etc/resolv.conf | head -1 | awk '{print $2}') mtu=9000 ks=nfs:$1:/backup/ks/$(uname -n).cfg biosdevname=0 nomodeset pcie_aspm=off" && reboot
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

if ! id $MY_SL_ADMIN; then
  groupadd -g $MY_SL_ADMIN_ID $MY_SL_ADMIN || $Error
  useradd -g $MY_SL_ADMIN -G wheel -u $MY_SL_ADMIN_ID $MY_SL_ADMIN || $Error
  echo $MY_SL_ADMIN_INIT_PW | passwd --stdin $MY_SL_ADMIN || $Error
  chage -d 0 $MY_SL_ADMIN || $Error
  cp -a /root/.ssh /home/$MY_SL_ADMIN/ || $Error
  chown -R $MY_SL_ADMIN:$MY_SL_ADMIN /home/$MY_SL_ADMIN/.ssh || $Error
fi

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

rpm -qa | LANG=C sort || $Error
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

cat /usr/Adaptec_Event_Monitor/Email_Notification_Status.cfg || $Error
cat /usr/Adaptec_Event_Monitor/Mail_Recipients.cfg || $Error
cat /usr/Adaptec_Event_Monitor/SMTP_Server_Details.cfg || $Error
cat /usr/Adaptec_Event_Monitor/NRMFSAConfig.xml  || $Error
sed -i -e 's/^nrm.debugMask.*$/nrm.debugMask = 2/' /usr/Adaptec_Event_Monitor/NRMConfig.conf || $Error

yum -y install \
 dialog \
 nfs-utils \
 python-setuptools \
 screen \
 telnet \
 watchdog || $Error

yum -y --enablerepo=epel install \
 bash-completion \
 fio \
 lsyncd \
 pv || $Error

yum -y --disablerepo=\* --enablerepo=elrepo install drbd84-utils kmod-drbd84 || $Error

wget http://iij.dl.sourceforge.jp/linux-ha/61791/pacemaker-1.0.13-2.1.el6.x86_64.repo.tar.gz || $Error
tar xzvf pacemaker-1.0.13-2.1.el6.x86_64.repo.tar.gz -C /tmp/ || $Error
yum -y -c /tmp/pacemaker-1.0.13-2.1.el6.x86_64.repo/pacemaker.repo install pacemaker heartbeat pm_extras pm_diskd || $Error
rm -rf /tmp/pacemaker-1.0.13-2.1.el6.x86_64.repo pacemaker-1.0.13-2.1.el6.x86_64.repo.tar.gz || $Error

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

cat << EOF | tee /etc/ha.d/param_nfsserver_for_backup || $Error
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

MY_SL_ADMIN=$MY_SL_ADMIN
SSH_CLIENTS=10.0.0.0/8

DRBD_SIZE=90G
DRBD_PASSWORD=password

NFS_CLIENTS=10.0.0.0/8

NFS_EXPORT_POINT=/backup
EOF

cat << 'EOF' | tee /etc/ha.d/param_all_nfsserver_for_backup || $Error
. /etc/ha.d/param_nfsserver_for_backup
HA_NETWORK_123=$(echo $HA_VIP | awk -F. '{print $1 "." $2 "." $3}')
HA_NETWORK_4=$(($(echo $HA_VIP | awk -F. '{print $4}') & -64))
HA_GATEWAY="$HA_NETWORK_123.$((HA_NETWORK_4+1))"
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
if [ "$(id)" != "$(id root)" ]; then
  echo; echo "You are not root user."
  exit 1
fi
. /etc/ha.d/param_all_nfsserver_for_backup
if [ $? -ne 0 ]; then
  echo; echo "You have not edited /etc/ha.d/param_nfsserver_for_backup yet."
  exit 1
fi
if [ ! "$HA1_NAME" ]; then
  echo; echo "You have not edited /etc/ha.d/param_nfsserver_for_backup yet."
  exit 1
fi
if [ ! "$HA2_NAME" ]; then
  echo; echo "You have not edited /etc/ha.d/param_nfsserver_for_backup yet."
  exit 1
fi
if [ ! "$HA1_IP" ]; then
  echo; echo "You have not edited /etc/ha.d/param_nfsserver_for_backup yet."
  exit 1
fi
if [ ! "$HA2_IP" ]; then
  echo; echo "You have not edited /etc/ha.d/param_nfsserver_for_backup yet."
  exit 1
fi
if [ ! "$HA_NAME" ]; then
  echo; echo "You have not edited /etc/ha.d/param_nfsserver_for_backup yet."
  exit 1
fi
if [ ! "$HA_VIP" ]; then
  echo; echo "You have not edited /etc/ha.d/param_nfsserver_for_backup yet."
  exit 1
fi
if [ ! "$HA_GATEWAY_NAME" ]; then
  echo; echo "You have not edited /etc/ha.d/param_nfsserver_for_backup yet."
  exit 1
fi
if [ ! "$HA1_HB_NAME" ]; then
  echo; echo "You have not edited /etc/ha.d/param_nfsserver_for_backup yet."
  exit 1
fi
if [ ! "$HA2_HB_NAME" ]; then
  echo; echo "You have not edited /etc/ha.d/param_nfsserver_for_backup yet."
  exit 1
fi
if [ ! "$HA1_HB_IP" ]; then
  echo; echo "You have not edited /etc/ha.d/param_nfsserver_for_backup yet."
  exit 1
fi
if [ ! "$HA2_HB_IP" ]; then
  echo; echo "You have not edited /etc/ha.d/param_nfsserver_for_backup yet."
  exit 1
fi
if [ ! "$MY_SL_ADMIN" ]; then
  echo; echo "You have not edited /etc/ha.d/param_nfsserver_for_backup yet."
  exit 1
fi
if [ ! "$DRBD_SIZE" ]; then
  echo; echo "You have not edited /etc/ha.d/param_nfsserver_for_backup yet."
  exit 1
fi
if [ ! "$DRBD_PASSWORD" ]; then
  echo; echo "You have not edited /etc/ha.d/param_nfsserver_for_backup yet."
  exit 1
fi
if [ ! "$NFS_CLIENTS" ]; then
  echo; echo "You have not edited /etc/ha.d/param_nfsserver_for_backup yet."
  exit 1
fi
if [ ! "$NFS_EXPORT_POINT" ]; then
  echo; echo "You have not edited /etc/ha.d/param_nfsserver_for_backup yet."
  exit 1
fi
if [ "$(uname -n)" = "$HA1_NAME" ]; then
  if ping -c 1 $HA_NAME; then
    INIT_MODE=SLAVE
  elif ping -c 1 $HA_NAME; then
    INIT_MODE=SLAVE
  elif ping -c 1 $HA_NAME; then
    INIT_MODE=SLAVE
  else
    INIT_MODE=MASTER
  fi
elif [ "$(uname -n)" = "$HA2_NAME" ]; then
  if ping -c 1 $HA_NAME; then
    INIT_MODE=SLAVE
  else
    echo; echo "No Active node: $HA_NAME"
    exit 1
  fi
else
  echo; echo "Mismatch hostname: $(uname -n) / $HA1_NAME / $HA2_NAME"
  exit 1
fi
if [ "$INIT_MODE" = "SLAVE" ]; then
  if ! ping -c 1 $HA_VIP; then
    echo; echo "No Active node: $HA_VIP"
    exit 1
  fi
  if ip addr show | grep -q " $HA_VIP/"; then
    echo "$(uname -n) is Active host"
    exit 1
  fi
fi
set -x
if [ "$1" != nohup ]; then
  nohup $0 nohup > mk_nfsserver_for_backup.log 2>&1 &
  chown $MY_SL_ADMIN:$MY_SL_ADMIN mk_nfsserver_for_backup.log
  exit 0
fi

if [ ! -e /dev/vg0/drbd0 ]; then
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
127.0.0.1       localhost.localdomain localhost
$HA_GATEWAY     $HA_GATEWAY_NAME $(echo $HA_GATEWAY_NAME | awk -F. '{print $1}')
$HA1_IP    $HA1_NAME $(echo $HA1_NAME | awk -F. '{print $1}')
$HA2_IP    $HA2_NAME $(echo $HA2_NAME | awk -F. '{print $1}')
$HA_VIP    $HA_NAME $(echo $HA_NAME | awk -F. '{print $1}')
$HA1_HB_IP     $HA1_HB_NAME $(echo $HA1_HB_NAME | awk -F. '{print $1}')
$HA2_HB_IP     $HA2_HB_NAME $(echo $HA2_HB_NAME | awk -F. '{print $1}')
EOF

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
-A INPUT -s $HA1_IP,$HA2_IP -j ACCEPT
-A INPUT -p tcp --dport 2049  -m tcp -m state --state NEW -s $NFS_CLIENTS -d $HA_VIP -j ACCEPT
-A INPUT -p udp --dport 2049  -m udp -m state --state NEW -s $NFS_CLIENTS -d $HA_VIP -j ACCEPT
-A INPUT -p tcp --dport 111   -m tcp -m state --state NEW -s $NFS_CLIENTS -d $HA_VIP -j ACCEPT
-A INPUT -p udp --dport 111   -m udp -m state --state NEW -s $NFS_CLIENTS -d $HA_VIP -j ACCEPT
-A INPUT -p tcp --dport 662   -m tcp -m state --state NEW -s $NFS_CLIENTS -d $HA_VIP -j ACCEPT
-A INPUT -p udp --dport 662   -m udp -m state --state NEW -s $NFS_CLIENTS -d $HA_VIP -j ACCEPT
-A INPUT -p tcp --dport 875   -m tcp -m state --state NEW -s $NFS_CLIENTS -d $HA_VIP -j ACCEPT
-A INPUT -p udp --dport 875   -m udp -m state --state NEW -s $NFS_CLIENTS -d $HA_VIP -j ACCEPT
-A INPUT -p tcp --dport 892   -m tcp -m state --state NEW -s $NFS_CLIENTS -d $HA_VIP -j ACCEPT
-A INPUT -p udp --dport 892   -m udp -m state --state NEW -s $NFS_CLIENTS -d $HA_VIP -j ACCEPT
-A INPUT -p tcp --dport 32803 -m tcp -m state --state NEW -s $NFS_CLIENTS -d $HA_VIP -j ACCEPT
-A INPUT -p udp --dport 32769 -m udp -m state --state NEW -s $NFS_CLIENTS -d $HA_VIP -j ACCEPT
-A INPUT -p tcp --dport 22    -m tcp -m state --state NEW -s $SSH_CLIENTS -j ACCEPT
-A INPUT -p icmp -s 10.0.0.0/8 -j ACCEPT
#-A INPUT -j LOG --log-prefix "IPTABLES_REJECT_PRIVATE : " --log-level=info
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

sed -i -e 's%^.* /var/log/messages$%*.info;mail.none;authpriv.none;cron.none;local1.none    /var/log/messages%' -e '/\/var\/log\/messages$/a local1.info                                             /var/log/ha-log' /etc/rsyslog.conf
/etc/init.d/rsyslog restart

cat << 'EOF' | tee /etc/logrotate.d/heartbeat

EOF
cat << 'EOF' | tee /etc/logrotate.d/syslog
/var/log/cron
/var/log/maillog
/var/log/messages
/var/log/ha-log
/var/log/secure
/var/log/spooler
{
    sharedscripts
    postrotate
        /bin/kill -HUP `cat /var/run/syslogd.pid 2> /dev/null` 2> /dev/null || true
    endscript
}
EOF

cat << 'EOF' | tee /etc/ha.d/authkeys
auth 1
1 crc
EOF
chmod 600 /etc/ha.d/authkeys
cat << EOF | tee /etc/ha.d/ha.cf
crm yes
debug 0
logfacility local1
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

NFS_CLIENTS=$(echo $NFS_CLIENTS | tr , " ")

cat << EOF | tee /etc/ha.d/nfsserver_for_backup.txt
primitive p_drbd_r0 ocf:linbit:drbd \\
  params drbd_resource="r0" \\
  op start   interval="0" timeout="240s" \\
  op monitor interval="31s" enabled="true" role="Master" timeout="20s" \\
  op monitor interval="29s" enabled="true" role="Slave"  timeout="20s" \\
  op notify  interval="0" timeout="90s" \\
  op stop    interval="0" timeout="120s" \\
  op promote interval="0" timeout="90s" \\
  op demote  interval="0" timeout="90s"
primitive p_vipcheck ocf:heartbeat:VIPcheck \\
  params target_ip="$HA_VIP" count="1" wait="10"  \\
  op start interval="0" timeout="90s" start_delay="4s" \\
  op stop  interval="0" timeout="60s"
primitive p_vip ocf:heartbeat:IPaddr2 \\
  params ip=$HA_VIP cidr_netmask=26 \\
  op start   interval="0"   timeout="20" \\
  op monitor interval="30s" timeout="20" \\
  op stop    interval="0"   timeout="20"
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
  clientspec="$NFS_CLIENTS" wait_for_leasetime_on_stop="false" \\
  op start interval="0" timeout="240s" \\
  op stop  interval="0" timeout="100s"
primitive p_exp_backup ocf:heartbeat:exportfs \\
  params fsid="1" directory="/export$NFS_EXPORT_POINT" \\
  options="rw,sync,mountpoint" \\
  clientspec="$NFS_CLIENTS" wait_for_leasetime_on_stop="false" \\
  op start   interval="0"   timeout="240s" \\
  op monitor interval="30s" \\
  op stop    interval="0"   timeout="100s" \\
  meta is-managed="true"
primitive p_exp_nfs3 ocf:heartbeat:exportfs \\
  params fsid="2" directory="$NFS_EXPORT_POINT" \\
  options="rw,sync" \\
  clientspec="$NFS_CLIENTS" wait_for_leasetime_on_stop="false" \\
  op start   interval="0"   timeout="240s" \\
  op monitor interval="30s" \\
  op stop    interval="0"   timeout="100s" \\
  meta is-managed="true"
group g_nfs p_vipcheck p_fs_export p_fs_nfs3 p_rpcbind p_nfslock p_nfsserver p_exp_root p_exp_backup p_exp_nfs3 p_vip
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

#dd if=/dev/zero of=/dev/vg0/drbd0 bs=1M
echo yes | drbdadm wipe-md r0 || exit 1
echo yes | drbdadm create-md r0 || exit 1
if [ "$INIT_MODE" = "MASTER" ]; then
  sed -i -e '/wfc-timeout/ s/^#wfc#//' /etc/drbd.d/global_common.conf
  /etc/init.d/drbd start
  sed -i -e '/wfc-timeout/ s/^\([^#]\)/#wfc#\1/' /etc/drbd.d/global_common.conf
#  drbdadm new-current-uuid --clear-bitmap r0/0
#  drbdadm primary all
  drbdadm primary --force all
  mkfs.ext4 /dev/drbd0
  tune2fs -c 0 -i 0 /dev/drbd0
  mkdir -p /export
  mkdir -p $NFS_EXPORT_POINT
  mkdir -p /var/lib/rpc_pipefs/
  mount /dev/drbd0 /export
  /etc/init.d/rpcbind start
  /etc/init.d/nfslock start
  /etc/init.d/nfs start
  /etc/init.d/nfs stop
  /etc/init.d/nfslock stop
  /etc/init.d/rpcbind stop
  umount /var/lib/nfs/rpc_pipefs/
  mv /var/lib/nfs /export/
  ln -s /export/nfs /var/lib/nfs
  rmdir /export/nfs/rpc_pipefs/
  ln -s /var/lib/rpc_pipefs /export/nfs/rpc_pipefs
  tar czvf /etc/ha.d/sshd.tgz /etc/ssh
  mkdir -p /export$NFS_EXPORT_POINT/system
  chmod 700 /export$NFS_EXPORT_POINT/system
  chown -R nfsnobody:nfsnobody /export$NFS_EXPORT_POINT
  umount /export/
  drbdadm secondary all
  /etc/init.d/drbd stop
  rm -f $(find /var/lib/pengine/) $(find /var/lib/heartbeat/crm/) /var/lib/heartbeat/hb_generation
  /etc/init.d/heartbeat start
  while ! crm_mon -1rfA | grep "Online: \[ $(uname -n) \]"; do sleep 5; done
  crm configure load update /etc/ha.d/nfsserver_for_backup.txt
  while ! crm_mon -1rfA | grep IPaddr2 | grep Started; do sleep 1; done
  mkdir -p /backup/ks
  chmod 700 /backup/ks
  mkdir -p /backup/co605/images
  chmod -R 700 /backup/co605
  wget http://mirrors.service.networklayer.com/centos/6.5/isos/x86_64/CentOS-6.5-x86_64-minimal.iso -O /backup/co605/CentOS-6.5-x86_64-minimal.iso
  mount -o loop /backup/co605/CentOS-6.5-x86_64-minimal.iso /mnt
  cp /mnt/images/{install.img,updates.img} /backup/co605/images/
  umount /mnt


  echo; echo "Next is on $HA2_NAME, and execute $0 $1"
elif [ "$INIT_MODE" = "SLAVE" ]; then
  mkdir -p /export
  mkdir -p $NFS_EXPORT_POINT
  mkdir -p /var/lib/rpc_pipefs/
  rm -rf /var/lib/nfs
  ln -s /export/nfs /var/lib/nfs
  scp -o StrictHostKeyChecking=no $MY_SL_ADMIN@$HA1_NAME:/etc/ha.d/sshd.tgz /etc/ha.d/
  tar xzvf /tmp/sshd.tgz -C /
  /etc/init.d/sshd restart
  sed -i -e '/wfc-timeout/ s/^\([^#]\)/#wfc#\1/' /etc/drbd.d/global_common.conf
  rm -f $(find /var/lib/pengine/) $(find /var/lib/heartbeat/crm/) /var/lib/heartbeat/hb_generation
  /etc/init.d/heartbeat start
  crm_mon -frA
else
  echo; echo "You have not edited /etc/ha.d/param_nfsserver_for_backup correctly."
  exit 1
fi
EOF_NFSSERVER_FOR_BACKUP
chmod 755 /etc/ha.d/mk_nfsserver_for_backup

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

#cat << 'EOF' | tee /rescue/mount || $Error
##!/bin/sh
#mkdir -p /backup
#[ "$1" ] && mount -t nfs $1:/backup /backup
#[ -d /proc/xen/ ] && DEV=xvda || DEV=sda
#mount -o rw,remount /dev/${DEV}2 /mnt/sysimage/
#mount /dev/${DEV}1 /mnt/sysimage/boot
#[ "$2" = "all" ] || exit 0
#mount -t proc /proc /mnt/sysimage/proc
#mount -t sysfs /sys /mnt/sysimage/sys
#mount --bind /dev /mnt/sysimage/dev
#EOF
#chmod 755 /rescue/mount || $Error

#cat << 'EOF' | tee /rescue/unmount || $Error
##!/bin/sh
#umount /mnt/sysimage/dev
#umount /mnt/sysimage/sys
#umount /mnt/sysimage/proc
#umount /mnt/sysimage/boot
#[ -d /proc/xen/ ] && DEV=xvda || DEV=sda
#mount -o ro,remount /dev/${DEV}2 /mnt/sysimage/
#umount /backup
#EOF
#chmod 755 /rescue/unmount || $Error

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

if [ "$MY_ROOT_PW" ]; then
  echo $MY_ROOT_PW | passwd --stdin root || $Error
else
  dd if=/dev/urandom bs=1 count=50 2> /dev/null | base64 | passwd --stdin root || $Error
fi

/usr/local/sbin/reboot_quick || $Error
