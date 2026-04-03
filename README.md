# VXLAN Controller

A VXLAN L2 overlay network controller, similar to EVPN but with IPv6 support and multi-AF routing.

Clients collect local MAC addresses and IPs, report them to the Controller. The Controller computes L2 routing (Floyd-Warshall shortest path) and distributes FDB entries to all clients via the Linux kernel.

## Why

FRR still lacks proper IPv6 VXLAN-EVPN support. This project provides a lightweight alternative with:

- **Dual-stack**: IPv4 and IPv6 underlay, with cross-AF transit routing
- **Multi-AF design**: Beyond v4/v6, supports arbitrary address families (e.g. `asia_v4`, `europe_v4`) for regional topologies
- **WireGuard-style encryption**: Noise IK handshake (X25519 + ChaCha20-Poly1305) on all control and data plane traffic
- **Controller failover**: Clients connect to multiple controllers, automatically switch on failure
- **Broadcast relay**: Controller relays ARP/ND across all AF listeners, no multicast FDB needed
- **Dynamic IP**: Runtime bind address changes via Unix socket API

## Architecture

```
┌──────────────┐         TCP (control)         ┌──────────────┐
│   Client 1   │◄────────────────────────────►  │  Controller  │
│  (node-1)    │         UDP (broadcast)        │  (node-10)   │
│              │◄────────────────────────────►  │              │
└──────┬───────┘                                └──────────────┘
       │ VXLAN
       │ FDB entries
       ▼
┌──────────────┐
│  br-vxlan    │
│  ├ vxlan-v4  │
│  ├ vxlan-v6  │
│  └ tap-inject│
└──────────────┘
```

## Build

```bash
go build -o vxlan-controller ./cmd/controller
go build -o vxlan-client ./cmd/client
go build -o keygen ./cmd/keygen
```

## Key Generation

Compatible with WireGuard key format:

```bash
# Using wg (if available)
wg genkey | tee privatekey | wg pubkey > publickey

# Using built-in keygen
./keygen genkey | tee privatekey | ./keygen pubkey > publickey
```

## Configuration

### Client (`client.yaml`)

```yaml
private_key: "<base64 private key>"
bridge_name: "br-vxlan"
neigh_suppress: false
init_timeout: 10
address_families:
  v4:
    enable: true
    bind_addr: "192.168.1.100"
    probe_port: 5010
    vxlan_name: "vxlan-v4"
    vxlan_vni: 100
    vxlan_mtu: 1400
    vxlan_dstport: 4789
    controllers:
      - public_key: "<controller pubkey>"
        endpoint: "10.0.0.1:5000"
  v6:
    enable: true
    bind_addr: "fd00::100"
    probe_port: 5010
    vxlan_name: "vxlan-v6"
    vxlan_vni: 100
    vxlan_mtu: 1400
    vxlan_dstport: 4789
    controllers:
      - public_key: "<controller pubkey>"
        endpoint: "[fd00::1]:5000"
```

### Controller (`controller.yaml`)

```yaml
private_key: "<base64 private key>"
client_offline_timeout: 300
sync_new_client_debounce: 2
sync_new_client_debounce_max: 10
topology_update_debounce: 1
topology_update_debounce_max: 5
probing:
  probe_interval_s: 60
  probe_times: 5
  in_probe_interval_ms: 200
  probe_timeout_ms: 1000
address_families:
  v4:
    enable: true
    bind_addr: "0.0.0.0"
    port: 5000
  v6:
    enable: true
    bind_addr: "::"
    port: 5000
allowed_clients:
  - public_key: "<client pubkey>"
    name: "node-1"
    additional_cost: 20
```

## Runtime API

Each client exposes a Unix socket at `/tmp/vxlan-client-<id>.sock`:

```bash
# Query current bind address
echo "GET_BIND_ADDR v4" | socat - UNIX-CONNECT:/tmp/vxlan-client-abcd1234.sock

# Update bind address (e.g. after IP change)
echo "UPDATE_BIND_ADDR v4 192.168.1.200" | socat - UNIX-CONNECT:/tmp/vxlan-client-abcd1234.sock
```

## Tests

Integration tests require root (network namespaces). 7 test suites with 62 total tests:

| # | Test | Description |
|---|------|-------------|
| 1 | `test_connectivity.sh` | Full mesh 30-pair ping (6 nodes) |
| 2 | `test_neigh_suppress.sh` | ARP suppression with priming |
| 3 | `test_controller_failover.sh` | Kill/restore both controllers |
| 4 | `test_transit_failure.sh` | Transit node failure and recovery |
| 5 | `test_broadcast_relay.sh` | Cross-AF broadcast relay |
| 6 | `test_dual_stack.sh` | IPv4-only ↔ IPv6-only via dual-stack transit |
| 7 | `test_ip_change.sh` | Runtime IP change via API |

```bash
# Run all tests
sudo bash tests/run_all.sh

# Run specific test
sudo bash tests/test_connectivity.sh
```

## License

See [LICENSE](LICENSE).
