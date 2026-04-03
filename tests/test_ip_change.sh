#!/bin/bash
# Test 7: IP change
# Verify that changing a client's bind_addr via the API:
# 1. Updates the VXLAN device's local source IP
# 2. Reconnects TCP/UDP sessions with the new IP
# 3. Controller updates client IP and pushes to other nodes
# 4. Other nodes update their FDB entries to use the new IP

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
echo "=== Test 7: IP change ==="

# Baseline
run_test "baseline: leaf-1 -> leaf-3" \
    ip netns exec "leaf-1" ping -c 2 -W 5 "${LEAF_SUBNET_V4}.3"
run_test "baseline: leaf-3 -> leaf-5" \
    ip netns exec "leaf-3" ping -c 2 -W 5 "${LEAF_SUBNET_V4}.5"
run_test "baseline: leaf-1 -> leaf-5" \
    ip netns exec "leaf-1" ping -c 2 -W 5 "${LEAF_SUBNET_V4}.5"

# Find sockets
SOCK_1=$(find_client_sock v4 "${V4_SUBNET}.1")
SOCK_3=$(find_client_sock v4 "${V4_SUBNET}.3")
SOCK_5=$(find_client_sock v6 "${V6_PREFIX}5")
echo "  Sockets: node-1=${SOCK_1:-none} node-3=${SOCK_3:-none} node-5=${SOCK_5:-none}"

# Change node-1 v4: .1 -> .101
echo "  Changing node-1 v4 IP: ${V4_SUBNET}.1 -> ${V4_SUBNET}.101"
ip netns exec "node-1" ip addr del "${V4_SUBNET}.1/24" dev eth-v4 2>/dev/null || true
ip netns exec "node-1" ip addr add "${V4_SUBNET}.101/24" dev eth-v4
if [ -n "$SOCK_1" ]; then
    resp=$(unix_sock_cmd "$SOCK_1" "UPDATE_BIND_ADDR v4 ${V4_SUBNET}.101" || true)
    echo "    API: $resp"
else
    echo "    WARNING: no socket for node-1"
fi

# Change node-3 v4: .3 -> .103
echo "  Changing node-3 v4 IP: ${V4_SUBNET}.3 -> ${V4_SUBNET}.103"
ip netns exec "node-3" ip addr del "${V4_SUBNET}.3/24" dev eth-v4 2>/dev/null || true
ip netns exec "node-3" ip addr add "${V4_SUBNET}.103/24" dev eth-v4
if [ -n "$SOCK_3" ]; then
    resp=$(unix_sock_cmd "$SOCK_3" "UPDATE_BIND_ADDR v4 ${V4_SUBNET}.103" || true)
    echo "    API: $resp"
else
    echo "    WARNING: no socket for node-3"
fi

# Change node-5 v6: ::5 -> ::105
echo "  Changing node-5 v6 IP: ${V6_PREFIX}5 -> ${V6_PREFIX}105"
ip netns exec "node-5" ip addr del "${V6_PREFIX}5/64" dev eth-v6 2>/dev/null || true
ip netns exec "node-5" ip addr add "${V6_PREFIX}105/64" dev eth-v6
if [ -n "$SOCK_5" ]; then
    resp=$(unix_sock_cmd "$SOCK_5" "UPDATE_BIND_ADDR v6 ${V6_PREFIX}105" || true)
    echo "    API: $resp"
else
    echo "    WARNING: no socket for node-5"
fi

echo "  Waiting 25s for reconnection and state sync..."
sleep 25

# Verify connectivity with new IPs
run_test "leaf-1 -> leaf-3 (after IP change)" \
    ip netns exec "leaf-1" ping -c 3 -W 10 "${LEAF_SUBNET_V4}.3"
run_test "leaf-3 -> leaf-5 (after IP change)" \
    ip netns exec "leaf-3" ping -c 3 -W 10 "${LEAF_SUBNET_V4}.5"
run_test "leaf-1 -> leaf-5 (after IP change)" \
    ip netns exec "leaf-1" ping -c 3 -W 10 "${LEAF_SUBNET_V4}.5"

# Verify unaffected nodes
run_test "leaf-2 -> leaf-4 (unaffected)" \
    ip netns exec "leaf-2" ping -c 3 -W 10 "${LEAF_SUBNET_V4}.4"
run_test "leaf-4 -> leaf-6 (unaffected)" \
    ip netns exec "leaf-4" ping -c 3 -W 10 "${LEAF_SUBNET_V4}.6"

print_results
exit $test_fail
