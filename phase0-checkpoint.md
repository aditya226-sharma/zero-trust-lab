# Phase 0 — Lab Environment (v2)

## Pre-reqs (verify before starting)
- [ ] Host has KVM/virtualization enabled: `kvm-ok` or `lscpu | grep Virtualization` returns VT-x/AMD-V
- [ ] `libvirtd` running: `systemctl status libvirtd`
- [ ] At least ~12 GB RAM and 100 GB disk free for 4 VMs
- [ ] Debian 12 netinstall ISO downloaded and reachable

## Files Created

| File | Purpose |
|------|---------|
| `networks/trusted-net.xml` | libvirt NAT network 10.10.1.0/24 with static DHCP for gateway, idp, app |
| `networks/untrusted-net.xml` | libvirt NAT network 10.10.2.0/24 with static DHCP for attacker |
| `scripts/create-vms.sh` | virt-install commands for all 4 VMs with correct MAC/IP assignments |
| `gateway/nftables.conf` | Default-deny nftables ruleset for gateway |

## Common Failure Modes

### 1. VM lands on wrong virtual network
**What it looks like:** A VM gets an IP in the wrong subnet (e.g., `virbr0` default network instead of `virbr1` for trusted-net).
**How to check:** `virsh domiflist <vm-name>` — verify the source network matches expected.
**Fix:** `virsh detach-interface <vm> network --persistent` then re-attach with correct `--network`.

### 2. nftables ruleset doesn't survive reboot
**What it looks like:** After `reboot`, all firewall rules are gone.
**How to check:** `sudo nft list ruleset` after reboot — empty or default-accept.
**Fix:** The ruleset must be loaded by a systemd service. Make sure you've run:
```bash
sudo cp /etc/nftables.conf /etc/nftables.conf
sudo systemctl enable nftables
```
Then verify: `sudo systemctl is-enabled nftables`.

### 3. Static DHCP assignment fails, VM gets random IP
**What it looks like:** A VM's IP doesn't match the expected static assignment from the network XML.
**How to check:** `virsh net-dhcp-leases trusted-net` — compare assigned IPs against the `<host mac=... ip=...>` entries.
**Fix:** The MAC address in the XML must match the VM's actual MAC exactly. `virsh domiflist <vm>` to see the MAC, then update the network XML.

## Rollback (save this before you need it)

```bash
# Flush ALL nftables rules to accept-all (use if you lock yourself out of a VM)
# Run via libvirt console or directly on the VM
sudo nft flush ruleset
sudo nft add table inet filter
sudo nft add chain inet filter input '{ type filter hook input priority 0; policy accept; }'
sudo nft add chain inet filter forward '{ type filter hook forward priority 0; policy accept; }'
sudo nft add chain inet filter output '{ type filter hook output priority 0; policy accept; }'

# If you're already locked out, use virsh console to run the above:
virsh console gateway  # (or whichever VM you locked yourself out of)

# To wipe a VM and recreate from scratch:
virsh destroy <vm-name>
virsh undefine <vm-name>
# Then re-run the virt-install command from create-vms.sh
```

## Checkpoint: attacker can reach gateway:443 but nothing else

### Prerequisite
All 4 VMs installed with Debian 12 minimal, networking configured per hints in create-vms.sh, gateway's nftables rules loaded:
```bash
sudo nft -f /etc/nftables.conf
sudo systemctl enable nftables
sudo systemctl restart nftables
```

### Test 1 — attacker can reach gateway:443 (should PASS)
```bash
# From attacker VM (10.10.2.10)
nc -zv 10.10.2.1 443
# OR
curl -vk --connect-timeout 5 https://10.10.2.1:443 2>&1 | head -5
```
**PASS output:** TCP handshake completes. `nc` reports "Connection succeeded". curl may show TLS error — that's fine, the TCP layer works.
**FAIL output (connection refused):** nftables blocking 443 — check ruleset.
**FAIL output (timeout):** No route to gateway at all — check gateway's untrusted-net interface or the libvirt network.

### Test 2 — attacker CANNOT reach idp:443 (should FAIL → prove access denied)
```bash
# From attacker VM
nc -zv -w 5 10.10.1.10 443
```
**PASS output (denial working):** `nc: connect to 10.10.1.10 port 443 (tcp) failed: Connection timed out` — attacker has no route to 10.10.1.0/24 directly.
**PASS output (alternative):** `nc: connect to 10.10.1.10 port 443 (tcp) failed: No route to host` — also correct, just means the ICMP response came back.
**FAIL output (control broken):** "Connection succeeded" — means untrusted-net has a route to trusted-net that shouldn't exist.

### Test 3 — attacker CANNOT reach app:443 directly (same as idp test)
```bash
nc -zv -w 5 10.10.1.20 443
```
Same pass/fail criteria as Test 2.

### Test 4 — trusted-net peer CAN reach gateway:443 (smoke test, should PASS)
```bash
# From idp or app VM
nc -zv 10.10.1.1 443
```
**PASS output:** "Connection succeeded".
**FAIL output:** Connection refused — gateway's nftables blocking trusted-net traffic to 443, which is too restrictive.

### Test 5 — nftables survives reboot
```bash
sudo reboot
# Wait for VM to come back, then:
sudo nft list ruleset | grep -q "policy drop" && echo "PERSISTS" || echo "LOST"
```
**PASS output:** `PERSISTS`

## Definition of Done

- [ ] All 4 VMs boot and get expected static/DHCP IPs on the correct network
- [ ] `attacker` can reach `gateway:443` (nc or curl succeeds)
- [ ] `attacker` CANNOT reach `idp` or `app` on any port (explicit failed connection, not a timeout you're guessing at)
- [ ] nftables ruleset survives a `gateway` reboot
- [ ] You have the rollback command saved somewhere before you need it

## Lab Shortcuts Flagged

1. **NAT networking** — lab uses NAT for internet access. Real deployment would use routed networking with no NAT.
2. **ICMP allowed unrestricted** — production environments should ratelimit or drop ICMP to prevent reconnaissance.
3. **No rate limiting on log prefix** — minimal rate limit set; production needs tuned rate limiting to prevent log flooding.
4. **Self-signed certs** — all HTTPS in this lab will use self-signed certs. Real deployment requires proper CA-signed certs or Let's Encrypt with automated renewal.
