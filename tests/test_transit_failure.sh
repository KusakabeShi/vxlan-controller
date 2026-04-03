#!/bin/bash
# Test 4: Transit node failure
# Node-3 is a dual-stack transit node. When it goes down, the controller
# recomputes RouteMatrix and traffic reroutes through other dual-stack nodes
# (node-4). When node-3 comes back, routes may restore through it.

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
echo "=== Test 4: Transit node failure ==="

# Baseline
run_test "baseline: leaf-1 -> leaf-5" \
    ip netns exec "leaf-1" ping -c 2 -W 5 "${LEAF_SUBNET_V4}.5"

# Kill Client-3
echo "  Killing Client-3..."
kill_by_log "client-3\|client.*3" || true
sleep 15  # Wait for offline detection + topology recompute

run_test "leaf-1 -> leaf-5 (node-3 down)" \
    ip netns exec "leaf-1" ping -c 3 -W 10 "${LEAF_SUBNET_V4}.5"

# Restore Client-3
echo "  Restarting Client-3..."
start_process "node-3" vxlan-client "$CLIENT_3_CONF" "client-3-2"
sleep 15  # Wait for reconnect + probe + topology update

run_test "leaf-1 -> leaf-5 (node-3 restored)" \
    ip netns exec "leaf-1" ping -c 3 -W 10 "${LEAF_SUBNET_V4}.5"

# Verify full connectivity restored
run_test "leaf-3 -> leaf-1 (node-3 restored)" \
    ip netns exec "leaf-3" ping -c 2 -W 5 "${LEAF_SUBNET_V4}.1"
run_test "leaf-3 -> leaf-5 (node-3 restored)" \
    ip netns exec "leaf-3" ping -c 2 -W 5 "${LEAF_SUBNET_V4}.5"

print_results
exit $test_fail
