# Phase 3 — Network Segmentation (WireGuard) (v2)

## Pre-reqs (verify before starting)
- [ ] WireGuard kernel module available: `modprobe wireguard` succeeds, `lsmod | grep wireguard` shows it loaded
- [ ] Phase 0's nftables baseline still in place: `sudo nft list ruleset | grep "policy drop"` returns something
- [ ] `wireguard-tools` installable: `apt install -y wireguard` (includes `wg` and `wg-quick`)
- [ ] Gateway has a static IP on trusted-net (10.10.1.1)

## Setup Steps

### On gateway VM (10.10.1.1):
```bash
# 1. Install WireGuard
sudo apt install -y wireguard

# 2. Generate server key pair
wg genkey | sudo tee /etc/wireguard/server.key
sudo chmod 600 /etc/wireguard/server.key
sudo cat /etc/wireguard/server.key | wg pubkey | sudo tee /etc/wireguard/server.pub

# 3. Deploy config
sudo cp gateway/wg0.conf /etc/wireguard/wg0.conf
# EDIT /etc/wireguard/wg0.conf to insert the server private key

# 4. Add the nftables rule: app's port 443 only via wg0
nft add rule inet filter input iif != wg0 tcp dport 443 drop
nft add rule inet filter forward iif != wg0 tcp dport 443 drop

# Make persistent — add these two lines to /etc/nftables.conf inside the input and forward chains:
#   iif != wg0 tcp dport 443 drop

# 5. Enable IP forwarding
echo 'net.ipv4.ip_forward=1' | sudo tee -a /etc/sysctl.conf
sudo sysctl -p

# 6. Start WireGuard
sudo systemctl enable --now wg-quick@wg0
sudo wg show
```

### On app VM (10.10.1.20):
```bash
# 1. Install WireGuard
sudo apt install -y wireguard

# 2. Generate client key pair
wg genkey | sudo tee /etc/wireguard/client.key
sudo chmod 600 /etc/wireguard/client.key
sudo cat /etc/wireguard/client.key | wg pubkey | sudo tee /etc/wireguard/client.pub
```

### Manual approval on gateway (the identity gate):
```bash
# 3. Run the approval script with app VM's public key
sudo bash scripts/wg-add-peer.sh "$(cat /etc/wireguard/client.pub)" "10.8.0.2/32" "app-vm"
```

### On app VM — create and start client config:
```bash
# 4. Create /etc/wireguard/wg0.conf on app VM using the client config snippet
# from the approval script's output
sudo systemctl enable --now wg-quick@wg0
sudo wg show
```

## Common Failure Modes

### 1. Peer config works on trusted-net but fails from untrusted-net (routing leak)
**What it looks like:** Connection works from app VM (which is on trusted-net) but testing the same app endpoint from any other path reveals a routing bypass.
**Why:** The nftables rule `iif != wg0 tcp dport 443 drop` only applies to traffic entering through the gateway's network interfaces. If the app VM has a NIC on trusted-net that isn't firewalled, traffic from other trusted-net VMs can still reach app:443 directly.
**How to check:** From a trusted-net VM WITHOUT WireGuard (e.g., idp VM): `nc -zv 10.10.1.20 443`. If this succeeds, the nftables rule is missing or in the wrong chain.
**Fix:** The nftables rule must be in BOTH the `input` chain AND the `forward` chain, AND there must be no other allow rule that shadows it. Also ensure the app VM itself has no default gateway on trusted-net that bypasses WireGuard.

### 2. nftables rule ordering — earlier accept rule shadows this new deny
**What it looks like:** The `iif != wg0 tcp dport 443 drop` rule is present in nftables but traffic still gets through.
**Why:** nftables checks rules in order and stops at the first match. If an earlier rule says "accept from trusted-net to any port", it will match before reaching the WireGuard rule.
**How to check:** `sudo nft list ruleset` — examine the input chain. Look for any `accept` rule that appears BEFORE the `iif != wg0 tcp dport 443 drop` rule and matches the same traffic.
**Fix:** Reorder the rules: put the WireGuard-specific drop rule BEFORE any broader accept rules. The safest approach is to put all drop rules first, then accepts.

### 3. wg0 interface doesn't come up on boot
**What it looks like:** `sudo wg show` returns nothing after reboot.
**How to check:** `sudo systemctl status wg-quick@wg0` — should show "active (exited)". `ip link show wg0` — should show the interface.
**Fix:** `sudo systemctl enable wg-quick@wg0`. If it still doesn't start, check for missing `PrivateKey` in the config file or a missing `/etc/wireguard/` directory.

## Rollback

```bash
# MANUAL peer revocation (this is what Phase 6's automation will call)
# Remove a peer by public key:
sudo wg set wg0 peer <peer-public-key> remove

# To permanently remove from the config file, edit /etc/wireguard/wg0.conf
# and delete the [Peer] section. Then restart:
sudo systemctl restart wg-quick@wg0

# Full WireGuard teardown:
sudo systemctl stop wg-quick@wg0
sudo systemctl disable wg-quick@wg0
sudo ip link delete wg0

# Remove nftables rules (undo the Phase 3 additions):
nft delete rule inet filter input handle <handle-number>
nft delete rule inet filter forward handle <handle-number>
# Find handle numbers: nft -a list ruleset
```

## Definition of Done

- [ ] A device on trusted-net WITHOUT an active tunnel cannot reach app:443
- [ ] A device WITH an approved tunnel can reach app:443
- [ ] You've manually run the peer-revoke process once and confirmed access drops immediately after
- [ ] You understand (not just copy-pasted) why this rule proves network location isn't implicit trust

## Why This Proves "Network Location ≠ Trust"

In a traditional perimeter model, being on the "trusted" subnet (10.10.1.0/24) is sufficient to reach any service. This phase's nftables rule `iif != wg0 tcp dport 443 drop` means: even if you're on the same physical network as the app, the only way through port 443 is an encrypted WireGuard tunnel. Network location alone grants nothing — you need the cryptographic key.

This is the core of zero-trust networking: **access is granted by possession of a cryptographic credential, not by physical location within a perimeter.**

## Lab Shortcuts Flagged

1. **No MTU tuning** — default WireGuard MTU works for lab VMs. Production may need path MTU discovery.
2. **No roaming support** — `PersistentKeepalive` is set but no endpoint roaming config. Fine for static lab VMs.
3. **Manual peer approval** — the script gates on my `yes` input. Real deployment needs automated, API-driven provisioning with certificate validation.
4. **Preshared key transmitted in script output** — the approval script prints the PSK to stdout. In production, deliver PSK via a secure channel.
