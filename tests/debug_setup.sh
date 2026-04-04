#!/usr/bin/env bash
set -euo pipefail

# Debug helper: sets up the same topology as tests/test_all.sh but does not auto-cleanup.
# Use `./tests/test_all.sh` for the real test suite.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN_DIR="${ROOT_DIR}/.bin"
WORK_DIR="${ROOT_DIR}/.test-work-debug"
LOG_DIR="${WORK_DIR}/logs"

mkdir -p "${BIN_DIR}" "${WORK_DIR}" "${LOG_DIR}"

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
}

echo "== setup underlay (no auto-cleanup) =="
ip link add br-lan_v4 type bridge 2>/dev/null || true
ip link set br-lan_v4 up
ip link add br-lan_v6 type bridge 2>/dev/null || true
ip link set br-lan_v6 up

for id in 1 2 3 4 5 6 10; do
  ip netns add "vx${id}" 2>/dev/null || true
  ns_exec "vx${id}" "ip link set lo up"
done

for id in 1 2 3 4 10; do
  ip link add "v4-${id}-root" type veth peer name "v4-${id}-ns" 2>/dev/null || true
  ip link set "v4-${id}-ns" netns "vx${id}" 2>/dev/null || true
  ip link set "v4-${id}-root" master br-lan_v4 2>/dev/null || true
  ip link set "v4-${id}-root" up 2>/dev/null || true
  ns_exec "vx${id}" "ip link set v4-${id}-ns up || true; ip addr add 192.168.47.${id}/24 dev v4-${id}-ns 2>/dev/null || true"
done

for id in 3 4 5 6 10; do
  ip link add "v6-${id}-root" type veth peer name "v6-${id}-ns" 2>/dev/null || true
  ip link set "v6-${id}-ns" netns "vx${id}" 2>/dev/null || true
  ip link set "v6-${id}-root" master br-lan_v6 2>/dev/null || true
  ip link set "v6-${id}-root" up 2>/dev/null || true
  ns_exec "vx${id}" "ip link set v6-${id}-ns up || true; ip -6 addr add fd87:4789::${id}/64 dev v6-${id}-ns 2>/dev/null || true"
done

for id in 1 2 3 4 5 6; do
  ip netns add "leaf${id}" 2>/dev/null || true
  ns_exec "leaf${id}" "ip link set lo up"
  ip link add "leaf${id}-root" type veth peer name "leaf${id}-ns" 2>/dev/null || true
  ip link set "leaf${id}-ns" netns "leaf${id}" 2>/dev/null || true
  ip link set "leaf${id}-root" netns "vx${id}" 2>/dev/null || true
  ns_exec "vx${id}" "ip link set leaf${id}-root up"
  ns_exec "leaf${id}" "ip link set leaf${id}-ns up; ip link set leaf${id}-ns name eth0; ip addr add 10.10.0.${id}/24 dev eth0; ip -6 addr add fd00:1::${id}/64 dev eth0"
done

echo "== start controllers/clients (log-level debug) =="
write_controller_cfg 4 "${WORK_DIR}/controller-4.yaml"
write_controller_cfg 10 "${WORK_DIR}/controller-10.yaml"
start_ns_proc vx4 "${LOG_DIR}/controller-4.log" "${BIN_DIR}/controller --config ${WORK_DIR}/controller-4.yaml --log-level debug"
start_ns_proc vx10 "${LOG_DIR}/controller-10.log" "${BIN_DIR}/controller --config ${WORK_DIR}/controller-10.yaml --log-level debug"

write_client_cfg 1 "${WORK_DIR}/client-1.yaml" false true false
write_client_cfg 2 "${WORK_DIR}/client-2.yaml" false true false
write_client_cfg 3 "${WORK_DIR}/client-3.yaml" false true true
write_client_cfg 4 "${WORK_DIR}/client-4.yaml" false true true
write_client_cfg 5 "${WORK_DIR}/client-5.yaml" false false true
write_client_cfg 6 "${WORK_DIR}/client-6.yaml" false false true
for id in 1 2 3 4 5 6; do
  start_ns_proc "vx${id}" "${LOG_DIR}/client-${id}.log" "${BIN_DIR}/client --config ${WORK_DIR}/client-${id}.yaml --log-level debug"
done

sleep 1
for id in 1 2 3 4 5 6; do
  ns_exec "vx${id}" "ip link set leaf${id}-root master br-vxlan"
done
sleep 6

echo "== quick diagnostics =="
ns_exec vx1 "bridge fdb show dev vxlan-v4 | head -n 20 || true"
ns_exec vx3 "bridge fdb show dev vxlan-v6 | head -n 20 || true"
ns_exec vx1 "ss -ntup | rg -n '19000|19001|17000|17001' || true"

echo "== try ping leaf1->leaf5 =="
ns_exec leaf1 "ping -c1 -W1 10.10.0.5 || true"

echo "Logs: ${LOG_DIR}"
echo "Namespaces left running. Manually cleanup with: ip netns del vx1 ...; ip link del br-lan_v4 br-lan_v6"

