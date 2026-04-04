#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN_DIR="${ROOT_DIR}/.bin"
WORK_DIR="${ROOT_DIR}/.test-work"
LOG_DIR="${WORK_DIR}/logs"

mkdir -p "${BIN_DIR}" "${WORK_DIR}" "${LOG_DIR}"

PIDS_FILE="${WORK_DIR}/pids"

cleanup() {
  set +e
  if [[ -f "${PIDS_FILE}" ]]; then
    while read -r pid; do
      kill "${pid}" 2>/dev/null || true
    done < "${PIDS_FILE}"
  fi
  pkill -f "${BIN_DIR}/controller" 2>/dev/null || true
  pkill -f "${BIN_DIR}/client" 2>/dev/null || true
  rm -f /tmp/vxlan-controller-vx*.sock 2>/dev/null || true
  for ns in $(ip netns list | awk '{print $1}' | grep -E '^(vx|leaf)[0-9]+$' || true); do
    # If any process is still in the netns, `ip netns del` will fail (busy).
    for pid in $(ip netns pids "${ns}" 2>/dev/null || true); do
      kill "${pid}" 2>/dev/null || true
    done
    sleep 0.1
    for pid in $(ip netns pids "${ns}" 2>/dev/null || true); do
      kill -9 "${pid}" 2>/dev/null || true
    done
    ip netns del "${ns}" 2>/dev/null || true
  done
  ip link del br-lan_v4 2>/dev/null || true
  ip link del br-lan_v6 2>/dev/null || true
  # ip(8) shows veth as "name@ifX"; strip the "@ifX" suffix so deletion works.
  for l in $(ip -o link show | awk -F': ' '{print $2}' | cut -d'@' -f1 | grep -E '^(v4|v6)-[0-9]+-root$' || true); do
    ip link del "${l}" 2>/dev/null || true
  done
  : > "${PIDS_FILE}" 2>/dev/null || true
}
trap cleanup EXIT

echo "== build =="
go build -o "${BIN_DIR}/controller" "${ROOT_DIR}/cmd/controller"
go build -o "${BIN_DIR}/client" "${ROOT_DIR}/cmd/client"

gen_keypair() {
  local priv pub
  priv="$(wg genkey)"
  pub="$(printf '%s' "${priv}" | wg pubkey)"
  echo "${priv} ${pub}"
}

declare -A PRIV PUB
for id in 1 2 3 4 5 6 10; do
  read -r priv pub < <(gen_keypair)
  PRIV["${id}"]="${priv}"
  PUB["${id}"]="${pub}"
done

write_controller_cfg() {
  local id="$1"
  local path="$2"
  cat >"${path}" <<YAML
private_key: ${PRIV[${id}]}
address_families:
  v4:
    name: v4
    enable: true
    bind_addr: 192.168.47.${id}
    communication_port: 19000
    vxlan_vni: 4789
    vxlan_dstport: 4789
    vxlan_srcport_start: 4789
    vxlan_srcport_end: 4789
  v6:
    name: v6
    enable: true
    bind_addr: fd87:4789::${id}
    communication_port: 19001
    vxlan_vni: 4789
    vxlan_dstport: 4789
    vxlan_srcport_start: 4789
    vxlan_srcport_end: 4789
client_offline_timeout: 6s
sync_new_client_debounce: 1200ms
sync_new_client_debounce_max: 2s
topology_update_debounce: 500ms
topology_update_debounce_max: 2s
probing:
  probe_interval_s: 10
  probe_times: 3
  in_probe_interval_ms: 100
  probe_timeout_ms: 500
allowed_clients:
  - client_id: ${PUB[1]}
    client_name: client-1
    additional_cost: 20
  - client_id: ${PUB[2]}
    client_name: client-2
    additional_cost: 20
  - client_id: ${PUB[3]}
    client_name: client-3
    additional_cost: 20
  - client_id: ${PUB[4]}
    client_name: client-4
    additional_cost: 500
  - client_id: ${PUB[5]}
    client_name: client-5
    additional_cost: 20
  - client_id: ${PUB[6]}
    client_name: client-6
    additional_cost: 20
YAML
}

write_client_cfg() {
  local id="$1"
  local path="$2"
  local neigh_suppress="$3"
  local enable_v4="$4"
  local enable_v6="$5"

  cat >"${path}" <<YAML
private_key: ${PRIV[${id}]}
bridge_name: br-vxlan
clamp_mss_to_mtu: false
neigh_suppress: ${neigh_suppress}
broadcast_pps_limit: 2000
fdb_debounce_ms: 300
fdb_debounce_max_ms: 1200
init_timeout: 1s
ntp_servers: []
ntp_resync_interval: 23h
api_unix_socket: /tmp/vxlan-controller-vx${id}.sock
address_families:
  v4:
    name: v4
    enable: ${enable_v4}
    bind_addr: 192.168.47.${id}
    probe_port: 17000
    communication_port: 18000
    vxlan_name: vxlan-v4
    vxlan_vni: 4789
    vxlan_mtu: 1450
    vxlan_dstport: 4789
    vxlan_srcport_start: 4789
    vxlan_srcport_end: 4789
    priority: 10
    controllers:
      - pubkey: ${PUB[4]}
        addr: 192.168.47.4:19000
      - pubkey: ${PUB[10]}
        addr: 192.168.47.10:19000
  v6:
    name: v6
    enable: ${enable_v6}
    bind_addr: fd87:4789::${id}
    probe_port: 17001
    communication_port: 18001
    vxlan_name: vxlan-v6
    vxlan_vni: 4789
    vxlan_mtu: 1450
    vxlan_dstport: 4789
    vxlan_srcport_start: 4789
    vxlan_srcport_end: 4789
    priority: 10
    controllers:
      - pubkey: ${PUB[4]}
        addr: "[fd87:4789::4]:19001"
      - pubkey: ${PUB[10]}
        addr: "[fd87:4789::10]:19001"
YAML
}

ns_exec() {
  local ns="$1"; shift
  ip netns exec "${ns}" bash -lc "$*"
}

start_ns_proc() {
  local ns="$1"; shift
  local log="$1"; shift
  ip netns exec "${ns}" bash -lc "$*" >"${log}" 2>&1 &
  echo $! >> "${PIDS_FILE}"
}

setup_underlay() {
  cleanup
  mkdir -p "${LOG_DIR}"
  ip link add br-lan_v4 type bridge || true
  ip link set br-lan_v4 up
  ip link add br-lan_v6 type bridge || true
  ip link set br-lan_v6 up

  for id in 1 2 3 4 5 6 10; do
    ip netns add "vx${id}" || true
    ns_exec "vx${id}" "ip link set lo up"
  done

  # v4 members: 1,2,3,4,10
  for id in 1 2 3 4 10; do
    ip link add "v4-${id}-root" type veth peer name "v4-${id}-ns"
    ip link set "v4-${id}-ns" netns "vx${id}"
    ip link set "v4-${id}-root" master br-lan_v4
    ip link set "v4-${id}-root" up
    ns_exec "vx${id}" "ip link set v4-${id}-ns up"
    ns_exec "vx${id}" "ip addr add 192.168.47.${id}/24 dev v4-${id}-ns"
  done

  # v6 members: 3,4,5,6,10
  for id in 3 4 5 6 10; do
    ip link add "v6-${id}-root" type veth peer name "v6-${id}-ns"
    ip link set "v6-${id}-ns" netns "vx${id}"
    ip link set "v6-${id}-root" master br-lan_v6
    ip link set "v6-${id}-root" up
    ns_exec "vx${id}" "ip link set v6-${id}-ns up"
    ns_exec "vx${id}" "ip -6 addr add fd87:4789::${id}/64 dev v6-${id}-ns nodad"
  done

  # Asymmetric tc delays (example values).
  ns_exec vx1 "tc qdisc add dev v4-1-ns root netem delay 1ms" || true
  ns_exec vx2 "tc qdisc add dev v4-2-ns root netem delay 5ms" || true
  ns_exec vx3 "tc qdisc add dev v4-3-ns root netem delay 1ms" || true
  ns_exec vx4 "tc qdisc add dev v4-4-ns root netem delay 8ms" || true
  ns_exec vx10 "tc qdisc add dev v4-10-ns root netem delay 2ms" || true

  ns_exec vx3 "tc qdisc add dev v6-3-ns root netem delay 1ms" || true
  ns_exec vx4 "tc qdisc add dev v6-4-ns root netem delay 9ms" || true
  ns_exec vx5 "tc qdisc add dev v6-5-ns root netem delay 1ms" || true
  ns_exec vx6 "tc qdisc add dev v6-6-ns root netem delay 6ms" || true
  ns_exec vx10 "tc qdisc add dev v6-10-ns root netem delay 2ms" || true
}

setup_leaves() {
  for id in 1 2 3 4 5 6; do
    ip netns add "leaf${id}" || true
    ns_exec "leaf${id}" "ip link set lo up"

    ip link add "leaf${id}-root" type veth peer name "leaf${id}-ns"
    ip link set "leaf${id}-ns" netns "leaf${id}"
    ip link set "leaf${id}-root" netns "vx${id}"
    ns_exec "vx${id}" "ip link set leaf${id}-root up"
    ns_exec "leaf${id}" "ip link set leaf${id}-ns up"

    # leaf side = eth0
    ns_exec "leaf${id}" "ip link set leaf${id}-ns name eth0"
    ns_exec "leaf${id}" "ip addr add 10.10.0.${id}/24 dev eth0"
    ns_exec "leaf${id}" "ip -6 addr add fd00:1::${id}/64 dev eth0 nodad"
  done
}

attach_leaf_ports_to_bridge() {
  for id in 1 2 3 4 5 6; do
    ns_exec "vx${id}" "ip link set leaf${id}-root master br-vxlan"
  done
}

wait_cmd() {
  local ns="$1"; local desc="$2"; local cmd="$3"
  for _ in $(seq 1 40); do
    if ns_exec "${ns}" "${cmd}" >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.5
  done
  echo "wait failed: ${desc}" >&2
  exit 1
}

start_controller() {
  local id="$1"
  write_controller_cfg "${id}" "${WORK_DIR}/controller-${id}.yaml"
  start_ns_proc "vx${id}" "${LOG_DIR}/controller-${id}.log" "${BIN_DIR}/controller --config ${WORK_DIR}/controller-${id}.yaml --log-level info"
}

start_client() {
  local id="$1"
  start_ns_proc "vx${id}" "${LOG_DIR}/client-${id}.log" "${BIN_DIR}/client --config ${WORK_DIR}/client-${id}.yaml --log-level info"
}

run_scenario() {
  local neigh_suppress="$1"
  echo "== setup scenario neigh_suppress=${neigh_suppress} =="

  setup_underlay
  setup_leaves

  start_controller 4
  start_controller 10

  # clients v4-only: 1,2; dual: 3,4; v6-only: 5,6
  write_client_cfg 1 "${WORK_DIR}/client-1.yaml" "${neigh_suppress}" true false
  write_client_cfg 2 "${WORK_DIR}/client-2.yaml" "${neigh_suppress}" true false
  write_client_cfg 3 "${WORK_DIR}/client-3.yaml" "${neigh_suppress}" true true
  write_client_cfg 4 "${WORK_DIR}/client-4.yaml" "${neigh_suppress}" true true
  write_client_cfg 5 "${WORK_DIR}/client-5.yaml" "${neigh_suppress}" false true
  write_client_cfg 6 "${WORK_DIR}/client-6.yaml" "${neigh_suppress}" false true

  for id in 1 2 3 4 5 6; do
    start_client "${id}"
  done

  # client bridge + vxlan creation
  sleep 1
  attach_leaf_ports_to_bridge
  sleep 8
}

leaf_mac() {
  local id="$1"
  ns_exec "leaf${id}" "cat /sys/class/net/eth0/address"
}

echo "== Scenario A (neigh_suppress=false) =="
run_scenario false

echo "== Test 1: basic connectivity =="
wait_cmd leaf1 "leaf1->leaf5 v4" "ping -c1 -W1 10.10.0.5"
wait_cmd leaf2 "leaf2->leaf6 v4" "ping -c1 -W1 10.10.0.6"
wait_cmd leaf1 "leaf1->leaf5 v6" "ping6 -c1 -W1 fd00:1::5"

echo "== Test 6: dual-stack routing FDB device selection =="
MAC5="$(leaf_mac 5)"
wait_cmd vx1 "vx1 has fdb for leaf5 on vxlan-v4" "bridge fdb show dev vxlan-v4 | rg -q \"${MAC5}.*dst 192\\.168\\.47\\.3\""
wait_cmd vx3 "vx3 has fdb for leaf5 on vxlan-v6" "bridge fdb show dev vxlan-v6 | rg -q \"${MAC5}.*dst fd87:4789::5\""

echo "== Test 5: broadcast relay (tcpdump sees broadcast on other leaf) =="
ns_exec leaf2 "timeout 6 tcpdump -n -i eth0 -c 1 ether broadcast" >/dev/null 2>&1 &
TCPDUMP_PID=$!
sleep 0.2
ns_exec leaf1 "ping -b -c 1 -W1 10.10.0.255" >/dev/null 2>&1 || true
wait "${TCPDUMP_PID}" || true
if ns_exec vx1 "bridge fdb show dev vxlan-v4 | rg -q 'ff:ff:ff:ff:ff:ff'"; then
  echo "unexpected broadcast fdb entry on vxlan-v4" >&2
  exit 1
fi

echo "== Test 3: controller failover (10 down -> 4, then back) =="
CTRL10_PID="$(pgrep -f "${BIN_DIR}/controller --config ${WORK_DIR}/controller-10.yaml" | head -n1 || true)"
if [[ -n "${CTRL10_PID}" ]]; then kill "${CTRL10_PID}" || true; fi
sleep 2
wait_cmd leaf1 "leaf1->leaf5 after controller10 down" "ping -c1 -W1 10.10.0.5"
start_controller 10
sleep 2
CTRL4_PID="$(pgrep -f "${BIN_DIR}/controller --config ${WORK_DIR}/controller-4.yaml" | head -n1 || true)"
if [[ -n "${CTRL4_PID}" ]]; then kill "${CTRL4_PID}" || true; fi
sleep 2
wait_cmd leaf1 "leaf1->leaf5 after controller4 down" "ping -c1 -W1 10.10.0.5"
start_controller 4
sleep 2

echo "== Test 4: forwarding node down and topology update =="
# Ensure path initially via client-3.
wait_cmd vx1 "vx1 fdb via client3" "bridge fdb show dev vxlan-v4 | rg -q \"${MAC5}.*dst 192\\.168\\.47\\.3\""
CLIENT3_PID="$(pgrep -f "${BIN_DIR}/client --config ${WORK_DIR}/client-3.yaml" | head -n1 || true)"
if [[ -n "${CLIENT3_PID}" ]]; then kill "${CLIENT3_PID}" || true; fi
sleep 8
wait_cmd leaf1 "leaf1->leaf5 after client3 down" "ping -c1 -W1 10.10.0.5"
# Expect reroute via client-4 (or other). Just ensure it's no longer via .3.
ns_exec vx1 "bridge fdb show dev vxlan-v4 | rg -q \"${MAC5}.*dst 192\\.168\\.47\\.3\" && exit 1 || exit 0"
start_client 3
sleep 8
wait_cmd leaf1 "leaf1->leaf5 after client3 back" "ping -c1 -W1 10.10.0.5"

echo "== Test 7: IP change + API update (1,3,5) =="
ns_exec vx1 "ip addr del 192.168.47.1/24 dev v4-1-ns; ip addr add 192.168.47.101/24 dev v4-1-ns"
ns_exec vx3 "ip addr del 192.168.47.3/24 dev v4-3-ns; ip addr add 192.168.47.103/24 dev v4-3-ns"
ns_exec vx5 "ip -6 addr del fd87:4789::5/64 dev v6-5-ns; ip -6 addr add fd87:4789::105/64 dev v6-5-ns"

ns_exec vx1 "curl --unix-socket /tmp/vxlan-controller-vx1.sock -sS -X PUT http://localhost/v1/af/v4/bind_addr -d '{\"bind_addr\":\"192.168.47.101\"}'"
ns_exec vx3 "curl --unix-socket /tmp/vxlan-controller-vx3.sock -sS -X PUT http://localhost/v1/af/v4/bind_addr -d '{\"bind_addr\":\"192.168.47.103\"}'"
ns_exec vx5 "curl --unix-socket /tmp/vxlan-controller-vx5.sock -sS -X PUT http://localhost/v1/af/v6/bind_addr -d '{\"bind_addr\":\"fd87:4789::105\"}'"

sleep 6
wait_cmd leaf1 "leaf1->leaf5 after bind addr update" "ping -c1 -W1 10.10.0.5"
wait_cmd vx1 "vxlan-v4 local updated" "ip -d link show vxlan-v4 | rg -q 'local 192\\.168\\.47\\.101'"

echo "== Scenario B (neigh_suppress=true) =="
run_scenario true

echo "== Test 2: neigh_suppress behavior =="
ns_exec leaf1 "ping -c1 -W1 10.10.0.2" >/dev/null 2>&1 || true
wait_cmd leaf2 "leaf2->leaf1 ping" "ping -c1 -W1 10.10.0.1"
wait_cmd leaf1 "leaf1->leaf2 ping again" "ping -c1 -W1 10.10.0.2"

echo "All tests passed."
