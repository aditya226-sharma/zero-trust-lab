#!/usr/bin/env bash
# wg-add-peer.sh — Interactive WireGuard peer provisioning script
#
# Adds a new WireGuard peer to the gateway, persists the configuration,
# and optionally registers the device in the posture store.
#
# Usage:
#   ./scripts/wg-add-peer.sh <public-key> <allowed-ip> <device-name> [--email <email>]
#
# Example:
#   ./scripts/wg-add-peer.sh ABC123...DEF 10.8.0.10 laptop-alice --email alice@zerotrust.lab
#
# Requirements:
#   - Run on the gateway VM (10.10.1.1)
#   - WireGuard tools installed (wg, wg-quick)
#   - Root or sudo access for wg set

set -euo pipefail

WG_INTERFACE="wg0"
PEERS_CONF="/etc/wireguard/peers.conf"
POSTURE_STORE="/opt/ztlab/gateway/shared-posture/posture.json"
WG_SUBNET="10.8.0"
LOG_FILE="/var/log/wg-peer-provisioning.log"

usage() {
    echo "Usage: $0 <public-key> <allowed-ip> <device-name> [--email <email>]"
    echo ""
    echo "Arguments:"
    echo "  public-key    WireGuard public key of the peer"
    echo "  allowed-ip    IP address to assign (e.g. 10.8.0.10)"
    echo "  device-name   Human-readable device name (e.g. laptop-alice)"
    echo "  --email       User email for posture tracking (optional)"
    echo ""
    echo "Example:"
    echo "  $0 ABC123...DEF 10.8.0.10 laptop-alice --email alice@zerotrust.lab"
    exit 1
}

log_event() {
    local level="$1"
    local message="$2"
    local timestamp
    timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    echo "[$timestamp] [$level] $message" | tee -a "$LOG_FILE"
}

validate_ip() {
    local ip="$1"
    if [[ ! "$ip" =~ ^10\.8\.0\.[0-9]+$ ]]; then
        echo "Error: IP must be in the 10.8.0.0/24 WireGuard subnet (got: $ip)" >&2
        exit 1
    fi
    local last_octet="${ip##*.}"
    if [[ "$last_octet" -lt 2 || "$last_octet" -gt 254 ]]; then
        echo "Error: IP last octet must be between 2 and 254 (got: $last_octet)" >&2
        exit 1
    fi
}

check_duplicate_ip() {
    local ip="$1"
    if wg show "$WG_INTERFACE" allowed-ips 2>/dev/null | grep -q "$ip"; then
        echo "Error: IP $ip is already assigned to another peer" >&2
        exit 1
    fi
}

check_duplicate_key() {
    local pubkey="$1"
    if wg show "$WG_INTERFACE" peers 2>/dev/null | grep -q "$pubkey"; then
        echo "Error: Public key already registered as a peer" >&2
        exit 1
    fi
}

assign_peer() {
    local pubkey="$1"
    local ip="$2"
    local name="$3"

    log_event "INFO" "Adding WireGuard peer: name=$name ip=$ip pubkey=${pubkey:0:12}..."

    wg set "$WG_INTERFACE" peer "$pubkey" allowed-ips "${ip}/32"

    if [[ ! -f "$PEERS_CONF" ]]; then
        touch "$PEERS_CONF"
    fi

    cat >> "$PEERS_CONF" <<EOF

# Peer: $name
# Added: $(date -u +"%Y-%m-%dT%H:%M:%SZ")
# AllowedIPs: ${ip}/32
[Peer]
PublicKey = $pubkey
AllowedIPs = ${ip}/32
EOF

    log_event "INFO" "Peer $name ($ip) added successfully"
    echo "Peer added: $name ($ip)"
}

register_posture() {
    local ip="$1"
    local name="$2"
    local email="${3:-}"

    if [[ ! -f "$POSTURE_STORE" ]]; then
        mkdir -p "$(dirname "$POSTURE_STORE")"
        echo '{}' > "$POSTURE_STORE"
    fi

    local now
    now=$(date +%s)

    local entry
    entry=$(python3 -c "
import json, sys
with open('$POSTURE_STORE', 'r') as f:
    store = json.load(f)
store['$ip'] = {
    'posture': 'unhealthy',
    'healthy': False,
    'device_id': '$name',
    'email': '$email',
    'registered_at': $now,
    'last_seen': 0,
    'signals': {
        'disk_encrypted': False,
        'patch_within_window': False,
        'no_blocklisted_process': False
    }
}
print(json.dumps(store, indent=2))
" 2>/dev/null)

    if [[ -n "$entry" ]]; then
        echo "$entry" > "$POSTURE_STORE"
        log_event "INFO" "Posture record created for $name ($ip) — status: unhealthy (awaiting first posture check)"
        echo "Posture record registered: $name ($ip) — awaiting first device check-in"
    else
        log_event "WARN" "Failed to create posture record for $name ($ip)"
        echo "Warning: Could not create posture record (check POSTURE_STORE path)"
    fi
}

print_summary() {
    local name="$1"
    local ip="$2"
    local pubkey="$3"

    echo ""
    echo "=== Peer Provisioning Complete ==="
    echo "  Device:   $name"
    echo "  IP:       $ip"
    echo "  Key:      ${pubkey:0:16}..."
    echo "  Status:   Awaiting posture check-in"
    echo ""
    echo "Next steps:"
    echo "  1. Share the client config with the device owner"
    echo "  2. Device must run posture_check.py to transition to 'healthy'"
    echo "  3. Monitor: wg show $WG_INTERFACE"
    echo "==================================="
}

# --- Main ---

if [[ $# -lt 3 ]]; then
    usage
fi

PUBLIC_KEY="$1"
ALLOWED_IP="$2"
DEVICE_NAME="$3"
EMAIL=""

shift 3
while [[ $# -gt 0 ]]; do
    case "$1" in
        --email)
            EMAIL="$2"
            shift 2
            ;;
        *)
            echo "Unknown option: $1" >&2
            usage
            ;;
    esac
done

validate_ip "$ALLOWED_IP"
check_duplicate_ip "$ALLOWED_IP"
check_duplicate_key "$PUBLIC_KEY"

echo "About to add peer:"
echo "  Device:  $DEVICE_NAME"
echo "  IP:      $ALLOWED_IP"
echo "  Key:     ${PUBLIC_KEY:0:16}..."
[[ -n "$EMAIL" ]] && echo "  Email:   $EMAIL"
echo ""
read -p "Confirm? [y/N] " -r
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Aborted."
    exit 0
fi

assign_peer "$PUBLIC_KEY" "$ALLOWED_IP" "$DEVICE_NAME"
register_posture "$ALLOWED_IP" "$DEVICE_NAME" "$EMAIL"
print_summary "$DEVICE_NAME" "$ALLOWED_IP" "$PUBLIC_KEY"
