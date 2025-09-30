# VXLAN Controller + Client

You are an expert Linux networking engineer and systems programmer. Implement a minimal but production-grade **EVPN-like VXLAN controller and client** in Go. Your implementation will use Linux netlink to manage VXLAN devices and the bridge FDB. The primary design goals are correctness, stability, and operational robustness.

---

## 1. Security & Identity
- **Authentication**: Mutual authentication is performed using WireGuard-style static public/private keys.
- **Client Identity**: A client's identity is its **public key**. The controllers maintain an allowlist.
- **Transport Security**:
  - A two-layer model is used for UDP communication.
  - **Encryption Layer (All Communication)**: All UDP packets, whether client-controller or client-client, MUST be encrypted using WireGuard-style cryptography (X25519 key exchange, ChaCha20-Poly1305 AEAD). A peer is identified by its public key.
  - **Reliability Layer (Client-Controller Only)**: For client-controller communication, a reliable UDP (RUDP) protocol (e.g., `go-rudp`) is layered on top of the encryption layer to ensure message integrity and ordered delivery for control plane messages.
  - **Reconnection**: For client-controller communication, it utilizes the API provied from SCTP implemented in rudp to track the communication between client-controller is lossless. If any disconnection happened, it trigger re-connection, upload local full mac address table and download full info from selected controller.

### 1.1 Unified Encryption Layer
- A standalone encryption layer encapsulates authentication, key management, and roaming logic per address family.
- Each instance is initialized once with `bind_addr`, `communication_port`, and the local private key; the resulting bound socket services both client-controller and client-client flows in that address family.
- The layer enforces WireGuard-style cryptography end-to-end: it derives per-peer symmetric keys, encrypts every datagram, and automatically re-handshakes when keys desynchronize or other cryptographic faults occur. These renegotiations are transparent to upper applications.
- Peers are registered via their public key together with initialization parameters: remote address (set to `0.0.0.0` or `::` to wait for roaming), remote port, and roaming mode. Registration returns a datagram-capable socket handle that higher layers use for messaging.
- The layer exposes APIs to update a peer's endpoint explicitly. Controllers use this to push authoritative endpoint changes while clients may store `0.0.0.0`/`::` until they learn the real address.
- Callers can register per-peer callbacks that fire when the layer accepts an endpoint change, allowing the controller to track and record fresh endpoints.
- Endpoint inspection APIs let higher layers retrieve the currently active remote address/port pair for any peer.
- The socket handle behaves like UDP. Reliability and ordering—such as `go-rudp` with SCTP semantics—are layered above this encryption layer when required.
- When a socket handle closes, either explicitly or because the encryption layer tears down the session after unrecoverable errors, the peer entry is removed. The public key remains the stable identifier for any future re-registration.
- Supported roaming behaviors are chosen per peer: `disabled`, `same_af`, or `all`. The layer inspects authenticated packets to decide whether to update the stored remote address when a peer presents a new source endpoint.
  - **`disabled`**: The new endpoint is ignored. The packet may be processed, but the stored endpoint for future outgoing packets is not updated.
  - **`same_af`**: The endpoint is updated only if the new source IP address has the same address family (e.g., IPv4 to IPv4) as the currently stored endpoint.
  - **`all`**: The endpoint is always updated to the new source IP:port, regardless of address family.
- When a legitimate endpoint change is accepted, the controller logic must bump the epoch and broadcast the updated endpoint so all clients stay aligned (§2.1).
- All traffic—both controller RPCs and peer probes—flows through this encryption layer, ensuring consistent security and addressing semantics per address family.

---

## 2. Control Plane Protocol & Multi-Controller Architecture
Clients connect to **all configured controllers simultaneously**. An RPC-style protocol over a reliable UDP (RUDP) transport is used. Messages should be serialized using **Protocol Buffers or Go's `gob`**.

- **Controller State Broadcast**: State update messages from a controller **must include**:
  - **Status**: `client_count`, `last_client_change_timestamp_minutes`, `epoch`.
  - **Configuration**: `vxlan` settings, `probing` parameters.
  - **Network View**: Contains updates for the controller's four authoritative datasets and is delivered as either a full snapshot or a delta from the previous epoch:
    1. `ClientEndpoints`: public IPv4/IPv6 endpoints for every registered client.
    2. `MacOwnership`: MAC address inventory mapped to the client that announced each MAC.
    3. `LatencyMatrix`: peer-to-peer latency samples for all clients aggregated from `AggregatedProbeResult` uploads.
    4. `RouteMatrix`: the Floyd-Warshall result describing the computed all-pairs least-cost paths between clients.
- **Message Types**:
  - `ClientStateRequest`: Client requests network state from a controller. Controllers ALWAYS respond with a full snapshot of all four datasets. Clients MUST issue this request at startup, immediately after any SCTP-detected reconnect event, and whenever their authoritative controller changes.
  - `ControllerStateUpdate`: Broadcast from a controller containing its status, configuration, and network view (all four datasets). Responses to `ClientStateRequest` are always full snapshots. Controllers may still push incremental (delta) updates proactively whenever any dataset changes to keep connected clients synchronized.
  - `AggregatedProbeResult`: Client uploads its aggregated RTT measurements for a completed cycle to all controllers.
  - `LocalMACAnnounce`: Client announces its local MAC addresses to all controllers. The controller then processes these changes, increments its epoch, and broadcasts the updates to all clients via `ControllerStateUpdate`.

### 2.1. Client Reconnection & State Synchronization
Upon connecting or reconnecting to a controller, a client MUST send a `ClientStateRequest` message and expect a full snapshot response.
- Reliable delivery and failure detection come from the SCTP layer embedded in the RUDP transport. If SCTP reports that the socket is closed or broken, the client MUST immediately reconnect, issue a `ClientStateRequest` as soon as the new session is up, and rebuild local state from the returned full snapshot.
- Clients also send a `ClientStateRequest` when their authoritative controller changes to ensure they synchronize with the new source of truth.

---

## 3. Client Authoritative Controller Selection (Stable Duration Model)
The client designates one controller as **Authoritative** and **only applies configuration and FDB updates** from this source.

The selection algorithm is:
1.  **Primary Criterion: Highest `client_count`**.
2.  **Tie-breaker 1: Oldest `last_client_change_timestamp_minutes`**. (Rewards stable controller-client connection)
3.  **Tie-breaker 2: Lowest `epoch`**.
4.  **Tie-breaker 3: Lowest `controller_id`**.

---

## 4. Client Startup & Validation
- **Initial Connection**: The client connects to all configured controllers.
- **Configuration Consistency Check**: Before proceeding to a fully operational state, the client **MUST** verify that all connected controllers are broadcasting the exact same configuration parameters (`vxlan` and `probing` settings). If any discrepancy is found, the client should log a critical error and refuse to start full operation until the configurations are aligned.

---

## 5. Client Networking Model
- **Dual VXLAN Devices**: Up to two VXLAN devices (one per AF), attached to the same Linux bridge.
- **Device Configuration**: The client receives `{ vni, port, mtu }` from the authoritative controller and uses `netlink` to configure devices. The `port` is for both source and destination.

### 5.1. Client Roaming & Endpoint Discovery
- **Endpoint Discovery**: The unified encryption layer learns a client's public endpoint from the source address of authenticated packets arriving on the established RUDP/SCTP session.
- **Roaming Mode Selection**: Per §1.1 the layer supports `disabled`, `same_af`, and `all`. This project pins modes as follows:
  - **Client-Controller Link**: Uses `same_af` so controllers accept endpoint moves within the same address family.
  - **Client-Client Link**: Uses `disabled`; clients only trust controller-advertised endpoints.
- **Update Propagation**: Controllers MUST use the encryption layer's endpoint-change callbacks to detect accepted updates, bump the state `epoch`, and broadcast `ControllerStateUpdate` messages so all peers synchronize their addressing.
 
### 5.2. NFTables Integration for MSS Clamping
- If `clamp_mss_to_mtu: true`, the client installs nftables rules to clamp TCP MSS for traffic traversing the VXLAN interfaces.
- The rules should be equivalent to:
    ```
    table bridge t {
        chain c {
            type filter hook forward priority filter; policy accept;
            oifname {vxlan_device_v4_name} ether type {ip, ip6} tcp flags syn tcp option maxseg size set rt mtu
            iifname {vxlan_device_v4_name} ether type {ip, ip6} tcp flags syn tcp option maxseg size set rt mtu
            oifname {vxlan_device_v6_name} ether type {ip, ip6} tcp flags syn tcp option maxseg size set rt mtu
            iifname {vxlan_device_v6_name} ether type {ip, ip6} tcp flags syn tcp option maxseg size set rt mtu
            // Add rules for other ether types if needed
        }
    }
    ```

---

## 6. Probing & Routing
- **Time Synchronization**: At startup, the client MUST synchronize with `ntp_servers` to calculate a stable **local time offset**. All time-related calculations must use this corrected time.

### 6.1. Probing Cycle & Measurement (RTT Model)
- **Synchronized Trigger**: Probing cycles are triggered at aligned UTC times. The start time for the next cycle must be calculated using the **NTP-corrected time** to ensure all clients start simultaneously, regardless of local clock drift. (`next_cycle_start = ceil(corrected_utc_now / probe_interval_s) * probe_interval_s`).
- **Probe ID**: The cycle's aligned start timestamp serves as the main `probe_id`.
- **Execution Flow (RTT Measurement)**:
  1.  At the start of a cycle, for each peer, the client initiates a series of probe requests.
  2.  A total of `probe_times` requests are sent, spaced `in_probe_interval_ms` apart. Each request has a `sub_id` (from 0 to `probe_times - 1`).
  3.  **Request**: Client A sends a `ProbeRequest` to Peer B containing `{probe_id, sub_id}`. Client A records its local send time for this pair.
  4.  **Response**: Peer B immediately replies with a `ProbeResponse` containing the same `{probe_id, sub_id}` and its own timestamp.
  5.  **RTT Calculation**: When Client A receives the response, it looks up its recorded send time and calculates the Round-Trip Time (RTT).

### 6.2. Local Aggregation & Upload
- **Result Collection**: After sending all probe requests in a cycle, the client waits for responses up to `probe_timeout_ms` for each request.
- **Aggregation**: Once the probing window for the cycle is over, the client aggregates the results for each peer:
  - It calculates the **median RTT** from all successful responses.
  - If no responses were received, the RTT is marked as `infinity`.
  - It records the success rate (`successful_probes / probe_times`) for potential future use.
- **Upload**: The client then uploads a single `AggregatedProbeResult` message for the completed cycle (`probe_id`) to **all connected controllers**. This message contains the median RTT and success rate for every peer it probed.

### 6.3. Controller Processing & Path Selection
- **Result Collection**: The controller collects `AggregatedProbeResult` messages from all clients.
- **Edge Weight Selection**: Before running the graph algorithm, for each pair of directly connected clients (e.g., A to B), the controller must choose a single best path (either v4 or v6) to determine the edge weight. The selection logic is:
  1.  **Liveness First**: If only one address family path has a finite RTT, select that path.
  2.  **Priority Rules**: If both paths are live:
      a. Select the path corresponding to the address family with the **lower `priority` number** (as announced by the source client A).
      b. If priorities are equal, select the path with the **lower median RTT**.
  3.  **base_latency_ms**: to prevent jitter for low-latency networks.(like 2ms to 5ms, which is 2.5 times larger, but it's not hugely important), it adds `base_latency_ms` to all edges before running the algorithm.
- **Path Calculation**: The controller uses the selected edge weights to run the **Floyd-Warshall algorithm**, computing the new routing table. This is then broadcast in subsequent `ControllerStateUpdate` messages.

---

## 7. Client FDB Programming (Decoupled Model)
- **Local MAC Discovery**: The client uses `netlink` subscriptions to monitor its local bridge and announces MACs to all controllers.
- **Data from Authoritative Controller**: The client only acts upon the `MAC Ownership` and `Routing Table` from its chosen authoritative source.
- **Client-Side FDB Resolution**: The client combines these two datasets to program its bridge FDB.

---

## 8. Observability
- **Structured Logging**: Use `log/slog` with configurable levels.
- **Metrics**: Expose Prometheus metrics via `/metrics` (e.g., `authoritative_controller_id`, `probe_cycle_id`).
- **Health Checks**: Provide a `/healthz` endpoint.

---

## 9. Configuration

### Controller (`controller.conf`)
- `private_key`: The controller's private key. Its public key is the `controller_id`.
- `listen_v4`, `listen_v6`
- `clients_allowlist`: An array of client public keys.
- `vxlan`: `{ "vni": 100, "port": 4789, "mtu": 1450 }`
- `probing`:
    - `probe_interval_s`: 60
    - `probe_times`: 5
    - `in_probe_interval_ms`: 200
    - `probe_timeout_ms`: 1000
    - **Constraint**: The operator must ensure timings allow for completion within a cycle. A valid configuration must satisfy: `probe_times * in_probe_interval_ms + probe_timeout_ms < (probe_interval_s - 1) * 1000`.
- `routing`: `{ "static_weight": false, "base_latency_ms" : 100, "static_latency_ms": a n*x matrix of latency values in milliseconds for all clients }`

### Client (`client.conf`)
- `private_key`: The client's private key.
- `bridge_name`
- `communication_port`
- `clamp_mss_to_mtu`: `true` or `false`.
- `address_families`:
  - `v4`: `{ "vxlan_name": "vxlan-v4", "bind_addr": "0.0.0.0","priority": 10  }`
  - `v6`: `{ "vxlan_name": "vxlan-v6", "bind_addr": "::", "priority": 20 }`
- `controllers`: An array of controller connection info.
``````json
  [
    {"public_key": "CONTROLLER_PUBKEY_1", "address_v4": "1.1.1.1:7890", "address_v6": "[2001::1]:7890"},
    {"public_key": "CONTROLLER_PUBKEY_2", "address_v4": "2.2.2.2:7890", "address_v6": "[2001::2]:7890"}
  ]
  ```
- `ntp_servers`: An array of NTP server addresses.
