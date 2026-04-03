#!/bin/bash
# Test 1: Basic connectivity (neigh_suppress=false)
# All leaf nodes should be able to ping each other.

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
echo "=== Test 1: Basic connectivity (neigh_suppress=false) ==="
for src in 1 2 3 4 5 6; do
    for dst in 1 2 3 4 5 6; do
        [ "$src" = "$dst" ] && continue
        run_test "leaf-$src -> leaf-$dst" \
            ip netns exec "leaf-$src" ping -c 3 -W 5 "${LEAF_SUBNET_V4}.$dst"
    done
done

print_results
exit $test_fail
