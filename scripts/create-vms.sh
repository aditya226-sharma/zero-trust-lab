#!/bin/bash
# Phase 0 — Create all 4 ZTLab VMs
# Run this on the KVM host (your machine, not inside any VM)
#
# Prerequisites:
#   sudo apt install virt-manager libvirt-daemon-system qemu-kvm
#   Download Debian 12 netinstall ISO to ./debian-12.iso
#   Adjust --disk path, --os-variant, and --cdrom as needed

ISO="./debian-12-netinst.iso"
POOL="default"   # or whatever your storage pool is named
BRIDGE="virbr0"  # your host bridge for external internet access on gateway

# Ensure networks exist first
echo "=== Defining libvirt networks ==="
sudo virsh net-define networks/trusted-net.xml
sudo virsh net-start trusted-net
sudo virsh net-autostart trusted-net

sudo virsh net-define networks/untrusted-net.xml
sudo virsh net-start untrusted-net
sudo virsh net-autostart untrusted-net

echo "=== Creating gateway VM (10.10.1.1) ==="
# Gateway has TWO NICs: trusted-net + untrusted-net (for attacker to reach :443)
virt-install \
  --name gateway \
  --memory 2048 \
  --vcpus 2 \
  --disk size=20,pool=$POOL \
  --os-variant debian12 \
  --cdrom $ISO \
  --network bridge=virbr1,mac=52:54:00:01:00:01 \
  --network bridge=virbr2,mac=52:54:00:02:00:01 \
  --graphics spice \
  --console pty,target_type=serial

echo "=== Creating idp VM (10.10.1.10) ==="
virt-install \
  --name idp \
  --memory 2048 \
  --vcpus 2 \
  --disk size=20,pool=$POOL \
  --os-variant debian12 \
  --cdrom $ISO \
  --network bridge=virbr1,mac=52:54:00:01:00:02 \
  --graphics spice \
  --console pty,target_type=serial

echo "=== Creating app VM (10.10.1.20) ==="
virt-install \
  --name app \
  --memory 2048 \
  --vcpus 2 \
  --disk size=20,pool=$POOL \
  --os-variant debian12 \
  --cdrom $ISO \
  --network bridge=virbr1,mac=52:54:00:01:00:03 \
  --graphics spice \
  --console pty,target_type=serial

echo "=== Creating attacker VM (10.10.2.10) ==="
# Attacker has ONE NIC on untrusted-net only
virt-install \
  --name attacker \
  --memory 2048 \
  --vcpus 2 \
  --disk size=20,pool=$POOL \
  --os-variant debian12 \
  --cdrom $ISO \
  --network bridge=virbr2,mac=52:54:00:02:00:02 \
  --graphics spice \
  --console pty,target_type=serial

echo "=== All VMs created. Use 'virsh list --all' to verify ==="
echo "=== Install Debian 12 minimal on each, then proceed to Phase 1 ==="

# Post-install network config hints:
# gateway: /etc/network/interfaces — set ens3 as 10.10.1.1/24 (trusted),
#          ens4 as 10.10.2.1/24 (untrusted), default route via your host
# idp:     /etc/network/interfaces — set ens3 as 10.10.1.10/24, gateway 10.10.1.1
# app:     /etc/network/interfaces — set ens3 as 10.10.1.20/24, gateway 10.10.1.1
# attacker: /etc/network/interfaces — set ens3 as 10.10.2.10/24, gateway 10.10.2.1
