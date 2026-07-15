#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
NAMESPACES="st-src st-r1 st-r2 st-dst"

cleanup() {
  for namespace in $NAMESPACES; do
    ip netns del "$namespace" 2>/dev/null || true
  done
}

if [ "$(id -u)" -ne 0 ]; then
  echo "netns_lab.sh must run as root" >&2
  exit 2
fi
if ! command -v ip >/dev/null 2>&1; then
  echo "iproute2 is required" >&2
  exit 2
fi
if ! command -v iptables >/dev/null 2>&1; then
  echo "iptables is required" >&2
  exit 2
fi

trap cleanup EXIT INT TERM
cleanup

for namespace in $NAMESPACES; do
  ip netns add "$namespace"
  ip -n "$namespace" link set lo up
done

ip link add st-s0 type veth peer name st-r10
ip link set st-s0 netns st-src
ip link set st-r10 netns st-r1
ip link add st-r11 type veth peer name st-r20
ip link set st-r11 netns st-r1
ip link set st-r20 netns st-r2
ip link add st-r21 type veth peer name st-d0
ip link set st-r21 netns st-r2
ip link set st-d0 netns st-dst

ip -n st-src addr add 10.10.1.2/24 dev st-s0
ip -n st-r1 addr add 10.10.1.1/24 dev st-r10
ip -n st-r1 addr add 10.10.2.1/24 dev st-r11
ip -n st-r2 addr add 10.10.2.2/24 dev st-r20
ip -n st-r2 addr add 10.10.3.1/24 dev st-r21
ip -n st-dst addr add 10.10.3.2/24 dev st-d0

for pair in "st-src st-s0" "st-r1 st-r10" "st-r1 st-r11" \
            "st-r2 st-r20" "st-r2 st-r21" "st-dst st-d0"; do
  set -- $pair
  ip -n "$1" link set "$2" up
done

ip -n st-src route add default via 10.10.1.1
ip -n st-r1 route add 10.10.3.0/24 via 10.10.2.2
ip -n st-r2 route add 10.10.1.0/24 via 10.10.2.1
ip -n st-dst route add default via 10.10.3.1
ip netns exec st-r1 sysctl -q -w net.ipv4.ip_forward=1
ip netns exec st-r2 sysctl -q -w net.ipv4.ip_forward=1

run_trace() {
  ip netns exec st-src env \
    PYTHONPATH="$ROOT/src" \
    PYTHONPYCACHEPREFIX=/tmp/stratatrace-pycache \
    python3 -m stratatrace --source 10.10.1.2 --profile fast \
      --canary-flows 1 --pacing-ms 0.2 -w 0.3 -m 5 10.10.3.2
}

echo "== transparent forwarding =="
run_trace

echo "== r2 suppresses TTL-expired replies: expect OPAQUE observation gap =="
ip netns exec st-r2 iptables -I OUTPUT -p icmp --icmp-type time-exceeded -j DROP
run_trace

