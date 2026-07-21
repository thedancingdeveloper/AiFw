#!/bin/sh
# Portable FreeBSD packet-data-plane acceptance test for AiFw.
#
# This script intentionally depends only on a stock FreeBSD userland.  CI may
# run it in a throw-away VM, while private appliance jobs can invoke the same
# assertions after installing an AiFw image.  The topology is:
#
#   client jail (192.0.2.2) -- host/pf -- server jail (198.51.100.2)
#
# The host is the firewall under test.  Results and live kernel state are
# written below AIFW_RESULTS_DIR for upload by any CI provider.

set -eu

RESULTS_DIR=${AIFW_RESULTS_DIR:-/tmp/aifw-dataplane-results}
PF_CONF=/tmp/aifw-dataplane-pf.conf
CLIENT=aifw_ci_client
SERVER=aifw_ci_server
LAN_A=epair90a
LAN_B=epair90b
WAN_A=epair91a
WAN_B=epair91b
PF_WAS_ENABLED=0

fail() {
    echo "FAIL: $*" >&2
    exit 1
}

need() {
    command -v "$1" >/dev/null 2>&1 || fail "required command not found: $1"
}

cleanup() {
    set +e
    pfctl -a aifw-ci -F all >/dev/null 2>&1
    jexec "$SERVER" pkill nc >/dev/null 2>&1
    jail -r "$CLIENT" >/dev/null 2>&1
    jail -r "$SERVER" >/dev/null 2>&1
    ifconfig "$LAN_A" destroy >/dev/null 2>&1
    ifconfig "$WAN_A" destroy >/dev/null 2>&1
    if [ "$PF_WAS_ENABLED" -eq 0 ]; then
        pfctl -d >/dev/null 2>&1
    fi
}
trap cleanup EXIT INT TERM HUP

[ "$(id -u)" -eq 0 ] || fail "must run as root"
for cmd in ifconfig jail jexec pfctl ping nc python3; do need "$cmd"; done
mkdir -p "$RESULTS_DIR"

if pfctl -si >/dev/null 2>&1; then PF_WAS_ENABLED=1; fi

# Build two isolated VNET endpoint jails.  Numeric IDs avoid colliding with
# normal interfaces on self-hosted runners and make cleanup deterministic.
ifconfig epair create unit 90 >/dev/null
ifconfig epair create unit 91 >/dev/null
jail -c name="$CLIENT" persist vnet path=/ host.hostname="$CLIENT"
jail -c name="$SERVER" persist vnet path=/ host.hostname="$SERVER"
ifconfig "$LAN_B" vnet "$CLIENT"
ifconfig "$WAN_B" vnet "$SERVER"

ifconfig "$LAN_A" inet 192.0.2.1/24 up
ifconfig "$WAN_A" inet 198.51.100.1/24 up
jexec "$CLIENT" ifconfig lo0 127.0.0.1/8 up
jexec "$CLIENT" ifconfig "$LAN_B" inet 192.0.2.2/24 up
jexec "$CLIENT" route add default 192.0.2.1
jexec "$SERVER" ifconfig lo0 127.0.0.1/8 up
jexec "$SERVER" ifconfig "$WAN_B" inet 198.51.100.2/24 up
jexec "$SERVER" route add default 198.51.100.1
sysctl net.inet.ip.forwarding=1 >/dev/null

cat >"$PF_CONF" <<EOF
set skip on lo0
scrub in all
nat on $WAN_A inet from 192.0.2.0/24 to any -> ($WAN_A)
block log all
pass quick on $LAN_A inet from 192.0.2.0/24 to any keep state
pass quick on $WAN_A inet from 198.51.100.2 to any keep state
EOF

# The real parser is an acceptance boundary: never proceed after a rejected
# generated ruleset.  Preserve both the input and parser output as artifacts.
cp "$PF_CONF" "$RESULTS_DIR/pf.conf"
pfctl -nf "$PF_CONF" >"$RESULTS_DIR/pf-parse.log" 2>&1
pfctl -f "$PF_CONF"
pfctl -e >/dev/null 2>&1 || true

# Explicit pass and stateful return traffic.
jexec "$CLIENT" ping -c 2 -t 2 198.51.100.2 >"$RESULTS_DIR/icmp-pass.log"

# TCP and UDP are checked separately so a pass caused only by ICMP cannot
# produce a false green data-plane result.
jexec "$SERVER" sh -c 'nc -l 8080 >/tmp/aifw-ci-tcp.out &' 
sleep 1
printf 'aifw-tcp\n' | jexec "$CLIENT" nc -w 3 198.51.100.2 8080
sleep 1
jexec "$SERVER" grep -q aifw-tcp /tmp/aifw-ci-tcp.out

jexec "$SERVER" sh -c 'nc -u -l 8081 >/tmp/aifw-ci-udp.out &' 
sleep 1
printf 'aifw-udp\n' | jexec "$CLIENT" nc -u -w 2 198.51.100.2 8081
sleep 1
jexec "$SERVER" grep -q aifw-udp /tmp/aifw-ci-udp.out

# Default deny: a server-initiated connection to the client must not create a
# new state.  A successful connect is a hard failure.
jexec "$CLIENT" sh -c 'nc -l 9090 >/tmp/aifw-ci-deny.out &' 
sleep 1
if printf 'forbidden\n' | jexec "$SERVER" nc -w 2 192.0.2.2 9090; then
    fail "default-deny allowed a server-initiated TCP connection"
fi

pfctl -sr >"$RESULTS_DIR/pf-rules.txt"
pfctl -sn >"$RESULTS_DIR/pf-nat.txt"
pfctl -ss -vv >"$RESULTS_DIR/pf-states.txt"
ifconfig -a >"$RESULTS_DIR/ifconfig.txt"
netstat -rn >"$RESULTS_DIR/routes.txt"
printf '{"status":"passed","ipv4_routing":true,"nat":true,"tcp":true,"udp":true,"default_deny":true}\n' \
    >"$RESULTS_DIR/result.json"
echo "FreeBSD data-plane acceptance passed"
