#!/bin/bash
# Test 2: neigh_suppress=true behavior
# With neigh_suppress enabled, the bridge suppresses ARP/ND and responds from
# its own neighbor table. Initial ping from A->B may fail because B's neighbor
# info hasn't been synced yet. After B->A ping (which populates B's neighbor
# info on A's bridge), A->B should succeed.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/helpers.sh"
trap cleanup EXIT

build_binaries
generate_keys
setup_topology

echo "=== Generating configurations (neigh_suppress=true) ==="
generate_all_configs true

start_controllers
start_clients
wait_converge

echo ""
echo "=== Test 2: neigh_suppress=true ==="

# Flush any cached ARP entries
for i in 1 2 3 4 5 6; do
    ip netns exec "leaf-$i" ip neigh flush dev "veth-leaf-l-$i" 2>/dev/null || true
done
sleep 1

# Step 1: leaf-1 -> leaf-2 may or may not work (depends on whether neighbor
# info is already synced). We don't assert this.
echo "  Initial leaf-1 -> leaf-2 (may fail, expected)..."
ip netns exec "leaf-1" ping -c 1 -W 3 "${LEAF_SUBNET_V4}.2" > /dev/null 2>&1 || true

# Step 2: leaf-2 -> leaf-1 (this populates leaf-1's MAC/IP on leaf-2's bridge)
echo "  Priming: leaf-2 -> leaf-1..."
ip netns exec "leaf-2" ping -c 2 -W 5 "${LEAF_SUBNET_V4}.1" > /dev/null 2>&1 || true

sleep 3  # Allow neighbor info to propagate

# Step 3: Now leaf-1 -> leaf-2 should work (both sides have neighbor info)
run_test "leaf-1 -> leaf-2 (after priming)" \
    ip netns exec "leaf-1" ping -c 3 -W 5 "${LEAF_SUBNET_V4}.2"

# Step 4: Verify bidirectional after both sides have exchanged
run_test "leaf-2 -> leaf-1 (after priming)" \
    ip netns exec "leaf-2" ping -c 3 -W 5 "${LEAF_SUBNET_V4}.1"

# Test cross-AF with neigh_suppress
echo "  Priming: leaf-5 -> leaf-3..."
ip netns exec "leaf-5" ping -c 2 -W 5 "${LEAF_SUBNET_V4}.3" > /dev/null 2>&1 || true
sleep 3
echo "  Priming: leaf-3 -> leaf-5..."
ip netns exec "leaf-3" ping -c 2 -W 5 "${LEAF_SUBNET_V4}.5" > /dev/null 2>&1 || true
sleep 3

run_test "leaf-3 -> leaf-5 (neigh_suppress, after priming)" \
    ip netns exec "leaf-3" ping -c 3 -W 5 "${LEAF_SUBNET_V4}.5"

run_test "leaf-5 -> leaf-3 (neigh_suppress, after priming)" \
    ip netns exec "leaf-5" ping -c 3 -W 5 "${LEAF_SUBNET_V4}.3"

print_results
exit $test_fail
