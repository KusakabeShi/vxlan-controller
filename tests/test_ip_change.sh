#!/bin/bash
# Test 7: IP change via autoip_interface
# Verify that changing a client's IP on a monitored interface:
# 1. Auto-detects the new IP via netlink addr events
# 2. Updates the VXLAN device's local source IP
# 3. Reconnects TCP/UDP sessions with the new IP
# 4. Controller updates client IP and pushes to other nodes
# 5. Other nodes update their FDB entries to use the new IP

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/helpers.sh"
trap cleanup EXIT

build_binaries
generate_keys
setup_topology

echo "=== Generating configurations ==="
# Use autoip_interface for nodes 1, 3, 5 (the ones that will change IP)
CTRL_4_CONF=$(write_controller_config 4 "$PRIV_4")
CTRL_10_CONF=$(write_controller_config 10 "$PRIV_10")
CLIENT_1_CONF=$(write_client_config 1 "$PRIV_1" false true)
CLIENT_2_CONF=$(write_client_config 2 "$PRIV_2" false false)
CLIENT_3_CONF=$(write_client_config 3 "$PRIV_3" false true)
CLIENT_4_CONF=$(write_client_config 4 "$PRIV_4" false false)
CLIENT_5_CONF=$(write_client_config 5 "$PRIV_5" false true)
CLIENT_6_CONF=$(write_client_config 6 "$PRIV_6" false false)

start_controllers
start_clients
wait_converge

echo ""
echo "=== Test 7: IP change via autoip_interface ==="

# Baseline
run_test "baseline: leaf-1 -> leaf-3" \
    ip netns exec "leaf-1" ping -c 2 -W 5 "${LEAF_SUBNET_V4}.3"
run_test "baseline: leaf-3 -> leaf-5" \
    ip netns exec "leaf-3" ping -c 2 -W 5 "${LEAF_SUBNET_V4}.5"
run_test "baseline: leaf-1 -> leaf-5" \
    ip netns exec "leaf-1" ping -c 2 -W 5 "${LEAF_SUBNET_V4}.5"

# Change node-1 v4: .1 -> .101
# autoip_interface should pick up the change automatically
echo "  Changing node-1 v4 IP: ${V4_SUBNET}.1 -> ${V4_SUBNET}.101"
ip netns exec "node-1" ip addr del "${V4_SUBNET}.1/24" dev eth-v4 2>/dev/null || true
ip netns exec "node-1" ip addr add "${V4_SUBNET}.101/24" dev eth-v4

# Change node-3 v4: .3 -> .103
echo "  Changing node-3 v4 IP: ${V4_SUBNET}.3 -> ${V4_SUBNET}.103"
ip netns exec "node-3" ip addr del "${V4_SUBNET}.3/24" dev eth-v4 2>/dev/null || true
ip netns exec "node-3" ip addr add "${V4_SUBNET}.103/24" dev eth-v4

# Change node-5 v6: ::5 -> ::105
echo "  Changing node-5 v6 IP: ${V6_PREFIX}5 -> ${V6_PREFIX}105"
ip netns exec "node-5" ip addr del "${V6_PREFIX}5/64" dev eth-v6 2>/dev/null || true
ip netns exec "node-5" ip addr add "${V6_PREFIX}105/64" dev eth-v6

# Wait for debounce (1s) + reconnection + state sync + probe cycle
echo "  Waiting 40s for auto-detect, reconnection and state sync..."
sleep 40

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
