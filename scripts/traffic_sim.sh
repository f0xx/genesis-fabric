#!/bin/sh
# Optional loss/delay injection. Requires CAP_NET_ADMIN and is not part of ctest.
# Usage: scripts/traffic_sim.sh <ifname> [delay_ms] [loss_percent]
# Restore with: scripts/traffic_sim.sh <ifname> clear
set -eu
if [ "$#" -lt 1 ]; then
    echo "usage: $0 <ifname> [delay_ms] [loss_percent] | $0 <ifname> clear" >&2
    exit 2
fi
if ! command -v tc >/dev/null 2>&1; then
    echo "tc (iproute2) is required" >&2
    exit 1
fi
iface=$1
if [ "${2:-}" = "clear" ]; then
    tc qdisc del dev "$iface" root 2>/dev/null || true
    exit 0
fi
delay=${2:-30}
loss=${3:-1}
tc qdisc del dev "$iface" root 2>/dev/null || true
tc qdisc add dev "$iface" root netem delay "${delay}ms" loss "${loss}%"
echo "netem on $iface delay=${delay}ms loss=${loss}%"
