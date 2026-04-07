#!/bin/bash
# Test 3: Controller failover
# 1. Normal operation, all leaves can communicate
# 2. Kill Controller-10, clients fallback to Controller-4
# 3. Verify connectivity
# 4. Restore Controller-10
# 5. Verify connectivity
# 6. Kill Controller-4, clients switch to Controller-10
# 7. Verify connectivity
# 8. Restore Controller-4, verify normal

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
echo "=== Test 3: Controller failover ==="

# Baseline
run_test "baseline: leaf-1 -> leaf-2" \
    ip netns exec "leaf-1" ping -c 2 -W 5 "${LEAF_SUBNET_V4}.2"
run_test "baseline: leaf-3 -> leaf-5" \
    ip netns exec "leaf-3" ping -c 2 -W 5 "${LEAF_SUBNET_V4}.5"

# Step 2: Kill Controller-10
echo "  Killing Controller-10..."
kill_by_log "controller-10\|ctrl.*10" || true
sleep 5

echo "  Testing with Controller-10 down..."
run_test "leaf-1 -> leaf-2 (ctrl-10 down)" \
    ip netns exec "leaf-1" ping -c 2 -W 5 "${LEAF_SUBNET_V4}.2"
run_test "leaf-3 -> leaf-5 (ctrl-10 down)" \
    ip netns exec "leaf-3" ping -c 2 -W 5 "${LEAF_SUBNET_V4}.5"

# Step 4: Restore Controller-10
echo "  Restarting Controller-10..."
start_process "node-10" controller "$CTRL_10_CONF" "ctrl-10-2"
sleep 8

run_test "leaf-1 -> leaf-6 (ctrl-10 restored)" \
    ip netns exec "leaf-1" ping -c 2 -W 5 "${LEAF_SUBNET_V4}.6"

# Step 6: Kill Controller-4
echo "  Killing Controller-4..."
kill_by_log "controller-4\|ctrl.*4" || true
sleep 5

echo "  Testing with Controller-4 down..."
run_test "leaf-1 -> leaf-2 (ctrl-4 down)" \
    ip netns exec "leaf-1" ping -c 2 -W 5 "${LEAF_SUBNET_V4}.2"
run_test "leaf-3 -> leaf-5 (ctrl-4 down)" \
    ip netns exec "leaf-3" ping -c 2 -W 5 "${LEAF_SUBNET_V4}.5"

# Step 8: Restore Controller-4
echo "  Restarting Controller-4..."
start_process "node-4" controller "$CTRL_4_CONF" "ctrl-4-2"
sleep 13

run_test "leaf-1 -> leaf-6 (ctrl-4 restored)" \
    ip netns exec "leaf-1" ping -c 2 -W 5 "${LEAF_SUBNET_V4}.6"
run_test "leaf-2 -> leaf-5 (ctrl-4 restored)" \
    ip netns exec "leaf-2" ping -c 2 -W 5 "${LEAF_SUBNET_V4}.5"

print_results
exit $test_fail
