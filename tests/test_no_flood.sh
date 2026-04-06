#!/bin/bash
# Test: Verify master FDB entries prevent unicast flooding
#
# Topology recap:
#   node-1 (v4 only) — node-3 (v4+v6 relay) — node-5 (v6 only)
#   Each node has a leaf attached to its bridge.
#
# Test logic:
#   leaf-1 pings leaf-5. Traffic traverses node-3 as a relay (v4→v6).
#   On node-3's bridge, with correct master FDB entries, the frame should
#   go from vxlan-v4 → vxlan-v6, NOT to leaf-3's veth port.
#
#   We tcpdump on leaf-3 to verify it does NOT see leaf-1↔leaf-5 unicast frames.
#   This proves master FDB entries are preventing unknown-unicast flooding.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/helpers.sh"
trap cleanup EXIT

build_binaries
generate_keys
setup_topology

echo "=== Generating configurations ==="
generate_all_configs false

start_controllers
start_clients
wait_converge

echo ""
echo "=== Test: No unicast flooding through relay ==="

# Get leaf MACs and IPs for reference
LEAF1_MAC=$(ip netns exec leaf-1 cat /sys/class/net/veth-leaf-l-1/address)
LEAF5_MAC=$(ip netns exec leaf-5 cat /sys/class/net/veth-leaf-l-5/address)
echo "  leaf-1 MAC: $LEAF1_MAC  IP: ${LEAF_SUBNET_V4}.1"
echo "  leaf-5 MAC: $LEAF5_MAC  IP: ${LEAF_SUBNET_V4}.5"

# 1. Verify master FDB entries exist on node-3's bridge
echo ""
echo "--- Checking master FDB entries on relay node-3 ---"
fdb_master=$(ip netns exec node-3 bridge fdb show | grep -c "master $BRIDGE_NAME" || true)
echo "  master FDB entries on node-3: $fdb_master"

fdb_self=$(ip netns exec node-3 bridge fdb show | grep -c "self" || true)
echo "  self FDB entries on node-3: $fdb_self"

run_test "node-3 has master FDB entries" test "$fdb_master" -gt 0

# 2. Verify basic connectivity first (leaf-1 → leaf-5 through relay)
run_test "leaf-1 -> leaf-5 reachable" \
    ip netns exec leaf-1 ping -c 3 -W 5 "${LEAF_SUBNET_V4}.5"

# 3. Start tcpdump on leaf-3 to watch for leaked unicast frames
echo ""
echo "--- Checking for unicast flood on leaf-3 ---"
PCAP="$TMPDIR/leaf3-flood.pcap"
# Only capture unicast frames (not multicast/broadcast) involving leaf-1 or leaf-5 MACs
ip netns exec leaf-3 tcpdump -i veth-leaf-l-3 -w "$PCAP" -c 100 \
    "not ether multicast and (ether src $LEAF1_MAC or ether src $LEAF5_MAC or ether dst $LEAF1_MAC or ether dst $LEAF5_MAC)" \
    > /dev/null 2>&1 &
TCPDUMP_PID=$!
CLEANUP_PIDS+=("$TCPDUMP_PID")
sleep 1

# 4. Generate unicast traffic: leaf-1 → leaf-5
echo "  Sending 10 pings leaf-1 -> leaf-5 ..."
ip netns exec leaf-1 ping -c 10 -W 3 -i 0.2 "${LEAF_SUBNET_V4}.5" > /dev/null 2>&1 || true

# Also send leaf-5 → leaf-1
echo "  Sending 10 pings leaf-5 -> leaf-1 ..."
ip netns exec leaf-5 ping -c 10 -W 3 -i 0.2 "${LEAF_SUBNET_V4}.1" > /dev/null 2>&1 || true

sleep 2

# 5. Stop tcpdump and count leaked frames
kill "$TCPDUMP_PID" 2>/dev/null || true
wait "$TCPDUMP_PID" 2>/dev/null || true
sleep 0.5

leaked=0
if [ -f "$PCAP" ]; then
    leaked=$(tcpdump -r "$PCAP" -n 2>/dev/null | wc -l)
fi
echo "  Unicast frames leaked to leaf-3: $leaked"

run_test "no unicast flood to leaf-3 (leaked=$leaked)" test "$leaked" -eq 0

# 6. Also check another uninvolved node: leaf-2
echo ""
echo "--- Checking for unicast flood on leaf-2 ---"
PCAP2="$TMPDIR/leaf2-flood.pcap"
ip netns exec leaf-2 tcpdump -i veth-leaf-l-2 -w "$PCAP2" -c 100 \
    "not ether multicast and (ether src $LEAF5_MAC or ether dst $LEAF5_MAC)" \
    > /dev/null 2>&1 &
TCPDUMP2_PID=$!
CLEANUP_PIDS+=("$TCPDUMP2_PID")
sleep 1

echo "  Sending 10 pings leaf-1 -> leaf-5 ..."
ip netns exec leaf-1 ping -c 10 -W 3 -i 0.2 "${LEAF_SUBNET_V4}.5" > /dev/null 2>&1 || true
sleep 2

kill "$TCPDUMP2_PID" 2>/dev/null || true
wait "$TCPDUMP2_PID" 2>/dev/null || true
sleep 0.5

leaked2=0
if [ -f "$PCAP2" ]; then
    leaked2=$(tcpdump -r "$PCAP2" -n 2>/dev/null | wc -l)
fi
echo "  Unicast frames leaked to leaf-2: $leaked2"

run_test "no unicast flood to leaf-2 (leaked=$leaked2)" test "$leaked2" -eq 0

# 7. Show bridge FDB state for debugging
echo ""
echo "--- Bridge FDB on node-3 (relay) ---"
ip netns exec node-3 bridge fdb show | grep -v "33:33:\|01:00:5e\|ff:ff:ff" | head -20

echo ""
echo "--- Bridge FDB on node-1 ---"
ip netns exec node-1 bridge fdb show | grep -v "33:33:\|01:00:5e\|ff:ff:ff" | head -20

print_results
exit $test_fail
