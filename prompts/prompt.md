# VXLAN Controller + Client

You are an expert Linux networking engineer and systems programmer. Implement a minimal but production-grade **EVPN-like VXLAN controller and client** in Go. Your implementation will use Linux netlink to manage VXLAN devices and the bridge FDB. The primary design goals are correctness, stability, and operational robustness.

---

## 1. Security & Identity
- **Authentication**: Mutual authentication is performed using WireGuard-style static public/private keys.
- **Client Identity**: A client's identity is its **public key**. The controllers maintain an allowlist.
- **Transport Security**:
  - **Control Plane Encryption (Client-Controller & Client-Client Control Messages)**: All control plane communication MUST be encrypted using WireGuard-style cryptography (X25519 key exchange, ChaCha20-Poly1305 AEAD). A peer is identified by its public key. This includes:
    - Client-Controller RPC messages (with RUDP/SCTP reliability layer)
    - Client-Client probe packets (ProbeRequest/ProbeResponse)
  - **Data Plane (VXLAN)**: VXLAN packets carrying actual network traffic are transmitted as **plain UDP packets without encryption**. These are sent to peers' VXLAN endpoints independently of the WireGuard encryption layer.
  - **Reliability Layer (Client-Controller Only)**: For client-controller communication, a reliable UDP (RUDP) protocol with **SCTP-like semantics** is layered on top of the encryption layer to ensure message integrity and ordered delivery for control plane messages. The RUDP layer MUST provide TCP-like semantics including retransmission, checksums, packet reordering, and connection timeout detection. This is NOT the kernel SCTP protocol, but an application-layer implementation providing similar reliability guarantees.
  - **Synchronization Strategy**: Under normal operation, incremental (delta) updates are used to minimize bandwidth. When inconsistency is detected (missing epochs, corrupted state, or after reconnection), a full state synchronization MUST be triggered.
  - **Reconnection**: When the SCTP layer reports a socket closure or timeout (indicating loss of communication), the client MUST immediately reconnect, perform a FullUpload (resubmit complete local state including MAC table), and execute a FullDownload (request full snapshot from controller).

### 1.1 Unified Encryption Layer (WireGuard Protocol)
A standalone encryption layer that fully implements the WireGuard protocol specification, encapsulating authentication, key management, and roaming logic per address family.

**Architecture**: This layer is implemented as a single object (suggest naming: `WireGuardTransport` or `EncryptionLayer`) that manages all WireGuard protocol operations. The layer itself supports dual-stack operation (can bind to both IPv4 and IPv6 simultaneously), but this project uses a single-stack-per-instance approach for simplicity.

**Per-Address-Family Instantiation (This Project's Approach)**:
- **Each node (controller or client) creates ONE EncryptionLayer instance per address family**.
- If a node has both `v4` and `v6` configurations, it creates TWO separate EncryptionLayer instances:
  - `encryptionLayerV4`: binds only to IPv4, manages IPv4 communication
  - `encryptionLayerV6`: binds only to IPv6, manages IPv6 communication
- Each EncryptionLayer instance is completely independent with its own:
  - UDP socket(s) bound to the specific address family
  - Peer table (keyed by public key)
  - Handshake state machines
  - Encryption keys

**Dual-Stack Communication Example**:
```
Client A config: v4_bind=10.0.0.1, v6_bind=2001:db8::1
Client B config: v4_bind=10.0.0.2, v6_bind=2001:db8::2

Client A creates:
- encLayerV4 = NewEncryptionLayer(privKey, "10.0.0.1", null, 51820)
  └── NewPeer(B_pubkey, "10.0.0.2", 51820, roaming) → socketAB_v4
- encLayerV6 = NewEncryptionLayer(privKey, null, "2001:db8::1", 51820)
  └── NewPeer(B_pubkey, "2001:db8::2", 51820, roaming) → socketAB_v6

Result: Two independent encrypted channels between A and B
- Probing uses both sockets to measure v4_latency and v6_latency separately
- Controller selects optimal path based on priority + latency
```

#### 1.1.1 Initialization & Socket Management
- **Initialization**: Each EncryptionLayer instance is initialized with:
  - Local `private_key` (same for all instances on the same node)
  - `bind_addr_v4` (IPv4 address, or `null` to disable IPv4)
  - `bind_addr_v6` (IPv6 address, or `null` to disable IPv6)
  - `communication_port` (UDP port, same for all instances on the same node)
- The layer binds UDP socket(s) on the specified address(es) and port, handling all WireGuard protocol messages (handshake + data) for the enabled address families.
- **This project's usage pattern**: Always pass exactly one non-null bind address per instance to create single-stack EncryptionLayers:
  ```go
  // IPv4-only instance
  encLayerV4 := NewEncryptionLayer(privKey, "10.0.0.1", nil, 51820)

  // IPv6-only instance
  encLayerV6 := NewEncryptionLayer(privKey, nil, "2001:db8::1", 51820)
  ```
- **Note**: The EncryptionLayer implementation supports dual-stack initialization (both addresses non-null) for future projects, but this project does not use that mode.

**API Design**:
```go
type EncryptionLayer interface {
    // Peer Management
    NewPeer(pubKey PublicKey, remoteAddr *net.IP, remotePort int, roamingMode RoamingMode) (PeerSocket, error)

    // Endpoint Management
    GetLocalEndpoint() *Endpoint  // Returns this instance's bind_addr:communication_port
    SetPeerEndpoint(pubKey PublicKey, addr net.IP, port int) error
    GetPeerEndpoint(pubKey PublicKey) *Endpoint

    // Lifecycle
    Close() error
}

type PeerSocket interface {
    // Datagram operations
    Send(data []byte) error
    Recv() ([]byte, error)  // Blocks until data available

    // Lifecycle
    Close() error  // Removes peer from encryption layer
}
```

**Peer Management**:
- `NewPeer(pubKey, remoteAddr, remotePort, roamingMode)` registers a new peer and returns a datagram-like socket handle.
- Each peer is identified by its `public_key` (unique within this EncryptionLayer instance).
- The same peer (identified by public key) can exist in multiple EncryptionLayer instances (one per address family).
  - Example: `encLayerV4.NewPeer(B_pubkey, ...)` and `encLayerV6.NewPeer(B_pubkey, ...)` create two independent sockets.
- Multiple calls to the same EncryptionLayer with the same `pubKey` return the same underlying peer socket (idempotent).
- The returned `PeerSocket` provides a datagram-like interface for sending/receiving plaintext data to/from that specific peer via this address family.
- Writing to a `PeerSocket` sends encrypted data to the corresponding peer (unless `remoteAddr = null`, see below).
- Reading from a `PeerSocket` returns decrypted data received from that peer.
- Calling `Close()` on a `PeerSocket` removes the peer entry from this EncryptionLayer instance only.

#### 1.1.2 WireGuard Cryptographic Protocol
The layer implements the complete WireGuard protocol as specified in the [WireGuard whitepaper](https://www.wireguard.com/papers/wireguard.pdf):

**Key Exchange (Noise_IKpsk2)**:
- Uses the Noise protocol framework with pattern `IKpsk2` (Interactive Handshake with Known Peer and Pre-Shared Key support).
- **Handshake Initiation** (`type 1`): Sender → Receiver
  - Ephemeral key generation using X25519
  - AEAD encryption with `HASH("WireGuard v1 zx2c4 Jason@zx2c4.com")` as the initial chaining key
  - Contains: sender index, unencrypted ephemeral public key, encrypted static public key, encrypted timestamp
  - **Retry Strategy**: Follow WireGuard protocol's exponential backoff for handshake retransmission (identical implementation).
- **Handshake Response** (`type 2`): Receiver → Sender
  - Completes the Noise handshake
  - Contains: sender index, receiver index, ephemeral public key, encrypted empty payload
- **Cookie Reply** (`type 3`): Not implemented in this project
- Handshake completes in 1-RTT; the initiator can immediately send data after receiving the response.

**Data Keys Derivation**:
- After successful handshake, derive two symmetric keys using HKDF-SHA256:
  - `transport_key_send`: for encrypting outgoing packets
  - `transport_key_recv`: for decrypting incoming packets
- Keys are derived from the final chaining key produced by the Noise handshake.
- Each peer maintains separate send/receive keys (4 keys total per session: 2 local, 2 remote).

**Data Packet Format** (`type 4`):
- Header: `type (1 byte) || receiver_index (4 bytes) || counter (8 bytes)`
- Payload: ChaCha20-Poly1305 AEAD encrypted data
- The `receiver_index` allows the receiver to quickly look up the correct session state.
- The `counter` is used as the nonce for AEAD and for replay protection.

**Connection-less Protocol**:
- Pure UDP-based; no TCP-style connection state machine.
- Each packet is self-contained with its receiver index.
- Lost handshake packets trigger retransmission after timeout (exponential backoff recommended).
- The encryption layer does not guarantee delivery; reliability is layered above (e.g., RUDP/SCTP for control plane).

**Nonce Management & Replay Protection**:
- Each data packet includes a 64-bit counter that monotonically increases.
- Sender increments its counter for every packet sent using a given key pair.
- Receiver maintains a sliding window (recommended size: 2048) to track seen counters and reject replays.
- When counter approaches `2^64 - 1` or after a configurable time/data threshold (recommended: 2 minutes or 2^60 bytes), automatically initiate rekey by starting a new handshake.

**Automatic Rekeying**:
- Transparently initiate a new handshake before counter exhaustion or time limit.
- Continue using old keys for decryption until the new handshake completes.
- After new keys are established, retire old keys after a grace period (to handle reordered packets).
- Rekeying is invisible to upper layers; they continue using the same socket handle.

#### 1.1.3 Peer Management & Endpoint Discovery
**Peer Registration**:
- Peers are registered via their public key together with initialization parameters:
  - `remote_addr`: IPv4/IPv6 address or **`null`** to defer endpoint configuration
  - `remote_port`: UDP port
  - `roaming_mode`: `disabled`, `same_af`, or `all`
- **Encryption Layer Behavior with `remote_addr = null`**:
  - When `remote_addr` is `null`, outbound packets written to the `PeerSocket` are **silently discarded** (not queued).
  - The peer entry remains valid and the socket is usable.
  - Inbound authenticated packets from this peer are still processed normally.
  - When roaming is enabled (`same_af` or `all`), the endpoint will be learned from the first authenticated incoming packet.
  - When roaming is disabled and `remote_addr = null`, the application layer MUST call `SetPeerEndpoint` to configure the endpoint before sending data.
- **Application Layer Strategies**:
  - **Controller**: Sets `remote_addr = null` with `roaming_mode = same_af`, waits for clients to initiate connections. The encryption layer will learn endpoints from authenticated incoming packets.
  - **Client-Controller**: Reads controller endpoints from configuration file at startup and provides them during `NewPeer` call.
  - **Client-Client**: Initially sets `remote_addr = null` with `roaming_mode = disabled`, waits for controller to broadcast peer endpoints via `ControllerStateUpdate`, then uses `SetPeerEndpoint` to configure the encryption layer.
- **Network Environment Assumption**: This design assumes all nodes have publicly reachable IP addresses (no NAT). Double-NAT scenarios where both peers have `remote_addr = null` are not supported, as neither peer can initiate the first packet.
- Registration returns a datagram-capable socket handle that higher layers use for messaging.

**Endpoint Update & Roaming**:
- The layer exposes APIs to update a peer's endpoint explicitly (`SetPeerEndpoint`). Controllers use this to push authoritative endpoint changes.
- Callers can register per-peer callbacks that fire when the layer accepts an endpoint change from an authenticated packet.
- Endpoint inspection APIs (`GetPeerEndpoint`) let higher layers retrieve the currently active remote address/port pair for any peer.
- Supported roaming behaviors are chosen per peer:
  - **`disabled`**: Authenticated packets from new source addresses are processed, but the stored endpoint is never updated automatically.
  - **`same_af`**: The endpoint is updated only if the new source IP has the same address family as the currently stored endpoint.
  - **`all`**: The endpoint is always updated to the new source IP:port, regardless of address family. Requires both `bind_addr_v4` and `bind_addr_v6` to be set.
- When a legitimate endpoint change is accepted (via roaming or explicit API), the controller logic must update `last_client_change_timestamp` and broadcast the updated endpoint so all clients stay aligned (§2.1).

**Socket Handle Lifecycle**:
- The socket handle behaves like UDP for sending/receiving. Reliability and ordering (e.g., `go-rudp` with SCTP semantics or TCP/IP stack from gVisor or self implement) are layered above when required.
- **Persistent Peer Entries**: Peer entries are persistent and stateless. The encryption layer does NOT maintain "connection" state.
  - Peer sockets never "disconnect" or "timeout" on their own.
  - The encryption layer automatically manages WireGuard handshakes and rekeying transparently.
  - Handshake failures, packet loss, or cryptographic errors do not affect peer persistence.
  - The layer will continuously retry handshakes with exponential backoff when needed.
- **No Automatic Cleanup**: The encryption layer NEVER automatically removes peer entries. Peers persist indefinitely until explicitly removed.
  - Controllers never call `Close()` on peer sockets. A client's peer entry (identified by its unique public key) exists for the lifetime of the controller process.
  - Clients only call `Close()` when permanently removing a peer (e.g., peer deleted from network configuration).
- **Lifecycle Management Responsibility**:
  - The RUDP/SCTP layer (built on top of encryption layer) is responsible for detecting connection timeouts and notifying the application layer.
  - Application layer decides when to close peer sockets based on higher-level logic (not encryption layer failures).
- **Thread Safety**: `Close()` on a `PeerSocket` is thread-safe. Any packets received after `Close()` are silently dropped.
- The public key remains the stable identifier for the peer throughout its lifecycle.

#### 1.1.4 Traffic Flow
- **Control Plane (Client-Controller)**: RPC messages are encrypted by the WireGuard layer, with RUDP/SCTP providing reliability on top of the encrypted channel.
- **Data Plane (Client-Client VXLAN)**: VXLAN packets carrying actual network traffic are transmitted as **plain UDP packets without encryption**. These packets are sent directly to the peer's VXLAN endpoint (UDP port configured in `vxlan.port`), bypassing the WireGuard encryption layer entirely.
- **Probing Packets (Client-Client)**: ProbeRequest/ProbeResponse messages are sent through the encrypted WireGuard connection. These are control messages but do not require RUDP reliability (probe loss is handled by aggregation logic).
- The WireGuard encryption layer multiplexes handshake packets (`type 1, 2`) and data packets (`type 4`) on the same UDP socket (using `communication_port`).
- Upper layers simply read/write plaintext; encryption/decryption and handshake management are fully encapsulated.

---

## 2. Control Plane Protocol & Multi-Controller Architecture
Clients connect to **all configured controllers simultaneously**. An RPC-style protocol over a reliable UDP (RUDP/SCTP) transport is used. Messages should be serialized using **Protocol Buffers or Go's `gob`**.

- **Controller State Broadcast**: State update messages from a controller **must include**:
  - **Status**: `client_count`, `last_client_change_timestamp` (Unix timestamp when the SCTP layer last detected a connection state change: new connection establishment, disconnection, or timeout).
  - **Configuration**: `vxlan` settings, `probing` parameters, `routing` parameters (including `base_latency_ms`).
  - **Network View**: Contains updates for the controller's three authoritative datasets and is delivered as either a full snapshot or a delta from the previous update:
    1. `ClientEndpoints`: public IPv4/IPv6 endpoints for every registered client.
    2. `MacOwnership`: MAC address inventory mapped to the client that announced each MAC.
    3. `RouteMatrix`: the Floyd-Warshall result describing the computed all-pairs shortest paths between clients. Data structure: `RouteMatrix[src][dst] = next_hop_client_pubkey` or empty/null (if unreachable). Does NOT contain latency information, only next hop routing decisions.
- **Message Types**:
  - `ClientStateRequest`: Client requests network state from a controller. Controllers ALWAYS respond with a full snapshot of all three datasets. Clients MUST issue this request at startup, immediately after any SCTP-detected reconnect event, and whenever their authoritative controller changes.
  - `ControllerStateUpdate`: Broadcast from a controller containing its status, configuration, and network view (all three datasets). Can be either:
    - **Full Snapshot**: Complete state of all three datasets (always sent in response to `ClientStateRequest`)
    - **Delta Update**: Incremental changes since the last update (proactively pushed by controller when state changes)
    - **Message Structure**:
      ```protobuf
      message ControllerStateUpdate {
          ControllerStatus status = 1;
          NetworkConfig config = 2;
          ClientEndpointsMap client_endpoints = 3;
          MacOwnershipMap mac_ownership = 4;
          RouteMatrixMap route_matrix = 5;
      }

      message ClientEndpointsMap {
          // key: client public_key
          map<string, ClientEndpoint> endpoints = 1;
      }

      message ClientEndpoint {
          optional string v4_endpoint = 1;  // "ip:port" for control plane
          optional string v6_endpoint = 2;
          optional string v4_vtep = 3;      // IP only, for VXLAN dst
          optional string v6_vtep = 4;
      }

      message RouteMatrixMap {
          // Outer key: source client public_key
          map<string, RouteMatrix> matrices = 1;
      }

      message RouteMatrix {
          // Inner key: target client public_key
          map<string, PathSpec> paths = 1;
      }

      message PathSpec {
          string address_family = 1;  // "v4" | "v6" | "" (unreachable)
          // Example: RouteMatrix[A][B] = {address_family: "v6"}
          // Means: Client A should use Client B's v6_vtep to reach B
      }
      ```
  - `ProbeRequest`: Issued by any controller to trigger a probing cycle. Contains a unique `probe_id` and source client's priority configuration. Clients only execute probing if the request comes from their authoritative controller; non-authoritative `ProbeRequest` messages are ignored.
    ```protobuf
    message ProbeRequest {
        double probe_id = 1;
        string source_client_id = 2;
        int32 v4_priority = 3;  // Source client's v4 priority
        int32 v6_priority = 4;  // Source client's v6 priority
    }
    ```
  - `ProbeRequestAck`: Client responds to `ProbeRequest` from its authoritative controller. Contains the same `probe_id`. This acknowledgment is sent to **all connected controllers** (not just the issuing controller).
  - `AggregatedProbeResult`: Client uploads its aggregated OWD measurements for a completed cycle to all controllers. Contains `probe_id` and per-peer path metrics.
    ```protobuf
    message AggregatedProbeResult {
        double probe_id = 1;
        string source_client_id = 2;
        map<string, PeerMetrics> path_metrics = 3;  // key: target client public_key
    }

    message PeerMetrics {
        optional double v4_latency_ms = 1;  // null if unreachable
        optional double v6_latency_ms = 2;
        bool v4_reachable = 3;
        bool v6_reachable = 4;
    }
    ```
  - `LocalMACAnnounce`: Client announces its local MAC addresses to all controllers. Each MAC entry includes a `learned_timestamp` (Unix timestamp when the MAC was learned/updated by the client). Can be either:
    - **Full Announcement**: Complete MAC table (sent during FullUpload)
    - **Delta Announcement**: Only changed MACs (sent when local bridge FDB changes, supports both add and remove operations)
  - **FullUpload**: A client-side operation that resends its complete local state. Implemented as a full `LocalMACAnnounce` (containing all current MACs).
  - **FullDownload**: A client-side operation that requests and applies a full controller snapshot (`ClientStateRequest` + full `ControllerStateUpdate` response).

### Full State Synchronization Workflows
- **FullUpload**
  - Triggered during initial startup and after any SCTP-detected reconnect.
  - The client compiles its authoritative local data set: every locally owned MAC address from the bridge FDB.
  - This data is sent to each connected controller via full `LocalMACAnnounce`.
  - Controllers treat the full upload as canonical, replace their stored state for that client, update `last_client_change_timestamp` (due to SCTP reconnection event), and broadcast updates to all clients via `ControllerStateUpdate`.
- **FullDownload**
  - Immediately follows each FullUpload and also runs whenever the authoritative controller changes.
  - The client issues a `ClientStateRequest` and waits for the matching full `ControllerStateUpdate` snapshot containing all three datasets (ClientEndpoints, MacOwnership, RouteMatrix).
  - After receipt, the client replaces any cached controller-derived state, re-evaluates authoritative controller selection if necessary, and reprograms its VXLAN/FDB tables using the fresh data.
  - **Inconsistency Detection**: If the client receives a delta update but detects missing intermediate updates or corruption (e.g., unknown reference), it MUST immediately issue a `ClientStateRequest` to perform a FullDownload and resynchronize.

### 2.1. Client State Management & Multi-Controller Synchronization

**Client-Side Controller State Tracking**:
- The client maintains a **separate state snapshot** for each connected controller.
- Each controller's state includes: `ClientEndpoints`, `MacOwnership`, `RouteMatrix`, and configuration parameters.
- The client continuously updates each controller's state snapshot when receiving `ControllerStateUpdate` messages from that controller.
- The client does NOT notify controllers when changing its authoritative controller selection. The authoritative selection is a local decision.

**Initialization Protocol**:
1. **Connection Phase**: The client connects to all configured controllers and immediately starts the `init_timeout` timer.
2. **FullDownload Phase**: The client issues `ClientStateRequest` to **all** controllers and waits for `ControllerStateUpdate` responses.
3. **FDB Monitoring Initialization**: While waiting for controller responses, the client:
   - Starts monitoring FDB changes on the configured `bridge_name` via netlink (RTNLGRP_NEIGH)
   - Buffers all FDB change events (but does not process them yet)
4. **Local MAC Discovery**: After receiving at least one `ControllerStateUpdate`, the client reads the current FDB snapshot from the bridge:
   - Use netlink RTM_GETNEIGH to query FDB entries
   - Filter: Only entries on `bridge_name` and its slave ports (vxlan-v4, vxlan-v6)
   - Exclude: Entries matching pattern `dst <peer_ip> self permanent` (controller-installed static entries)
   - Build initial `local_mac_db` from filtered entries
5. **FullUpload Phase**: The client uploads its complete `local_mac_db` (full MAC table with `learned_timestamp`) to **all** controllers.
6. **Process Buffered FDB Events**: The client processes all buffered FDB change events accumulated during initialization as incremental updates.
7. **Initialization Mode**: While waiting for responses, the client enters **initialization mode**:
   - The client collects `ControllerStateUpdate` messages from all controllers and updates each controller's state snapshot.
   - The client continuously re-evaluates the authoritative controller selection algorithm (§3) but does NOT yet apply any FDB programming.
   - The client ignores any `ProbeRequest` messages during initialization (does not execute probing).
8. **Exit Initialization Mode**: The client exits initialization mode when:
   - All controllers have sent their initial `ControllerStateUpdate`, OR
   - The `init_timeout` expires (whichever comes first)
9. **Initialization Success Check**: After the timeout expires or all responses received:
   - If **at least one** controller successfully sent a `ControllerStateUpdate`, proceed to step 10.
   - If **no controllers** responded (all failed), the client logs a critical error and terminates.
10. **FDB Programming**: The client selects the authoritative controller from the successfully initialized controllers (using the algorithm in §3) and programs its FDB entries using that controller's state snapshot.
11. **Begin Normal Operation**: The client begins accepting and executing `ProbeRequest` messages from its authoritative controller.

**Rationale**: During startup, `client_count` and `last_client_change_timestamp` may fluctuate rapidly as clients connect. The `init_timeout` prevents premature FDB programming and allows the client to wait for a stable authoritative controller selection.

**SCTP Layer Semantics**:
- The SCTP layer MUST behave like TCP: it provides reliable, ordered delivery with retransmission, checksums, packet reordering, and timeout detection.
- The SCTP layer operates independently of the underlying UDP encryption layer. Transient UDP failures (disconnection/reconnection) that recover within the SCTP timeout period will trigger SCTP retransmissions but will NOT cause SCTP connection failure.
- When SCTP detects an unrecoverable error (timeout after all retries exhausted), it closes the connection and reports an error to the application layer. The peer's SCTP layer should also close the connection.

**Client-Side Reconnection Protocol**:
When the client's SCTP layer reports connection failure for a specific controller:
1. Close the SCTP connection to that controller
2. Re-establish a new SCTP connection to the controller
3. Mark that controller's state snapshot as **stale**
4. Perform a FullUpload to resubmit complete local state (full MAC table with `learned_timestamp` for each MAC)
5. Issue a `ClientStateRequest` to perform a FullDownload
6. When the full `ControllerStateUpdate` is received, update that controller's state snapshot and mark it as **synchronized**
7. Re-evaluate authoritative controller selection (§3)
8. If the authoritative controller changed, reprogram FDB entries using the new authoritative controller's state

**Controller-Side Connection Handling**:
- When the controller's SCTP layer detects a client connection failure, the controller marks the client as offline, updates `last_client_change_timestamp`, and waits for the client to reconnect.
- If the client reconnects, the controller accepts the new SCTP connection. If the client had an existing (but failed) SCTP session, the controller closes the old session and replaces it with the new one.
- If the client does NOT reconnect within a configurable timeout (`client_offline_timeout`), the controller:
  1. Deletes all MAC addresses owned by that client from `MacOwnership`
  2. Recomputes the `RouteMatrix` (excluding the offline client)
  3. Broadcasts a `ControllerStateUpdate` to all remaining clients

**Authoritative Controller Change (After Initialization)**:
- When the authoritative controller changes (detected via the selection algorithm in §3), the client silently switches to using the new authoritative controller's state snapshot for FDB programming.
- The client does NOT notify any controllers about this change.
- The client does NOT perform a new FullUpload or FullDownload; it simply uses the already-maintained state snapshot from the new authoritative controller.

---

## 3. Client Authoritative Controller Selection (Stable Duration Model)
**Controller Synchronization Architecture**:
- Controllers do NOT synchronize with each other. Each controller independently maintains its own view of the network state.
- Clients connect to all configured controllers and upload their state (MACs, probe results) to all controllers.
- Each client independently selects ONE controller as **Authoritative** and ONLY applies configuration and FDB updates from that source. Updates from non-authoritative controllers are ignored.
- Because all clients use the same selection algorithm and receive the same controller status information, they will converge on the same authoritative controller.

**Selection Algorithm** (applied independently by each client):
1. **Primary Criterion: Highest `client_count`** (most clients connected)
2. **Tie-breaker 1: Oldest `last_client_change_timestamp`** (rewards stable controller-client connections; smaller timestamp = longer stability)
3. **Tie-breaker 2: Lowest `controller_id`** (public key comparison for deterministic tie-breaking)

**Controller State Update**:
- When the SCTP layer detects a client connection breakage (via timeout/socket closure), the controller updates its `last_client_change_timestamp` to the current Unix timestamp and decrements `client_count`.
- When a new client connects, the controller increments `client_count` and updates `last_client_change_timestamp`.

**MAC Address Conflicts**:
- Controllers do not coordinate MAC ownership. If a client announces a MAC that conflicts with another client's announcement, the controller compares the `learned_timestamp` values and keeps the entry with the **newest timestamp** (highest value).
- If timestamps are equal, the controller keeps the most recently received announcement (last-write-wins).
- Note: In a properly configured network, MAC addresses within the same bridge domain should be unique. Conflicts indicate misconfiguration or VM migration.

Once a new authoritative controller is selected, the client performs only a FullDownload against that controller before applying any configuration or FDB updates.

---

## 4. Client Startup & Validation
- **Initial Connection**: The client connects to all configured controllers.
- **Bidirectional Configuration Synchronization**: The client performs a two-way configuration exchange with all controllers:
  1. **Client-side configuration initialization**: The client initializes its local configuration to `null` (no configuration loaded yet).
  2. **FullUpload**: The client uploads its complete local state (MAC table) to all controllers. This upload includes the client's current configuration (which is `null` during initial startup).
  3. **FullDownload**: The client issues a `ClientStateRequest` to all controllers and receives full `ControllerStateUpdate` responses containing configuration parameters (`vxlan`, `probing`, `routing` including `base_latency_ms`).
  4. **Configuration Verification**:
     - If all controllers return identical configurations, the client accepts this configuration and stores it locally.
     - **Controller-side detection**: When a controller receives a `FullUpload` with a non-null configuration that differs from the controller's own configuration, the controller MUST log a critical error showing the configuration differences and terminate. This prevents configuration drift in an already-running network.
  5. **Client-side detection**: If the client receives different configurations from different controllers during initial startup, it MUST log a critical error showing the configuration differences and refuse to start.
- **Rationale**: This bidirectional check ensures:
  - New clients joining an existing network detect configuration mismatches immediately.
  - Controllers detect when an already-synchronized client has a different configuration (indicating controller misconfiguration).
  - Both client and controller will refuse to operate until configurations are aligned.

---

## 5. Client Networking Model
- **Dual VXLAN Devices**: Up to two VXLAN devices (one per AF), attached to the same Linux bridge.
- **Device Configuration**: The client receives `{ vni, port, mtu }` from the authoritative controller and creates VXLAN devices using:
  ```bash
  ip link add {vxlan_name} type vxlan id {vni} local {bind_addr} ttl 255 dstport {port} srcport {port} {port}
  ```
  - The Linux kernel automatically handles the VXLAN UDP socket; no additional user-space UDP socket is required.
  - The `port` parameter specifies both the source and destination UDP port for VXLAN encapsulation.
  - `bind_addr` is the local IP address (from `address_families.v4.bind_addr` or `address_families.v6.bind_addr`) used as the VXLAN tunnel source.
- **Endpoint Terminology**:
  - **Control Endpoint**: `IP:communication_port` used for encrypted WireGuard control plane traffic (client-controller RPC, client-client probes).
  - **Data Endpoint / VTEP Address**: The IP address used for VXLAN data plane traffic. When programming FDB entries, only the IP portion of the peer's endpoint is used (without port, since the VXLAN port is fixed by configuration).
  - The `ClientEndpoints` dataset contains the full `IP:port` for control plane communication. When resolving VXLAN destinations, clients extract only the IP portion.

### 5.1. Client Roaming & Endpoint Discovery
- **Endpoint Discovery**: The unified encryption layer learns a client's public endpoint from the source address of authenticated packets arriving on the established RUDP/SCTP session.
- **Roaming Mode Selection**: Per §1.1 the layer supports `disabled`, `same_af`, and `all`. This project pins modes as follows:
  - **Client-Controller Link**: Uses `same_af` so controllers accept endpoint moves within the same address family (e.g., client NAT address change).
  - **Client-Client Link**: Uses `disabled`; clients only trust controller-advertised endpoints and use `SetPeerEndpoint` to update them.
- **Update Propagation**: When a controller detects an endpoint change (via the encryption layer's roaming callback), it MUST update `last_client_change_timestamp` and broadcast a `ControllerStateUpdate` message containing the new endpoint in the `ClientEndpoints` dataset so all peers can synchronize their peer tables.
 
### 5.2. NFTables Integration for MSS Clamping

**Purpose**: MSS clamping ONLY. No routing logic.

**Why MSS Clamping**: VXLAN adds overhead (50 bytes for IPv4, 70 bytes for IPv6 outer header). To prevent fragmentation, TCP MSS must be reduced.

**When to Apply**: If `clamp_mss_to_mtu: true` in client config, the client installs nftables rules to clamp TCP MSS for traffic traversing the VXLAN interfaces.

**Bridge Table Requirement**: Because VXLAN devices are attached to a Linux bridge and packets are forwarded within the bridge (L2), we must use `table bridge` instead of `table inet` (which is for L3 forwarding).

**Supported Traffic**: This implementation only supports `ip` and `ip6` ether types. VLAN (802.1Q) and QinQ (802.1ad) are not supported.

**Rules**:
```nft
table bridge vxlan_mss {
    chain forward {
        type filter hook forward priority filter; policy accept;

        # Clamp MSS for IPv4 and IPv6 traffic traversing VXLAN devices
        # MSS calculation: config.vxlan.mtu - 40 (TCP 20 bytes + IP 20 bytes)
        # Using rt mtu for dynamic adjustment based on routing table

        oifname "vxlan-v4" ether type {ip, ip6} tcp flags syn tcp option maxseg size set rt mtu
        iifname "vxlan-v4" ether type {ip, ip6} tcp flags syn tcp option maxseg size set rt mtu
        oifname "vxlan-v6" ether type {ip, ip6} tcp flags syn tcp option maxseg size set rt mtu
        iifname "vxlan-v6" ether type {ip, ip6} tcp flags syn tcp option maxseg size set rt mtu
    }
}
```

**Note**:
- The `ether type {ip, ip6}` filter ensures we only process IPv4 and IPv6 traffic.
- The MSS value should be calculated as `config.vxlan.mtu - 40` to account for TCP (20 bytes) and IP (20 bytes) headers.
- `rt mtu` dynamically uses the routing table MTU value for the destination.

---

## 6. Probing & Routing
- **Time Synchronization**: At startup, the client MUST attempt to synchronize with `ntp_servers` to calculate a stable **local time offset**. If NTP synchronization fails (all servers unreachable or timeout), the client logs a critical warning and continues with offset = 0 (uses local clock). The operator is responsible for ensuring proper NTP synchronization; clock skew will cause incorrect OWD measurements. All time-related calculations must use the corrected time (local_time + offset).

### 6.1. Probing Cycle & Measurement (OWD Model)

**Probing Triggers & Controller Coordination**:
All probing cycles are centrally coordinated by controllers. The probing protocol consists of two independent phases:

**Phase 1: ProbeRequest Issuance** (Decoupled from collection)
Each controller independently issues `ProbeRequest` messages based on:
1. **Periodic (Scheduled)**: Calculate aligned UTC times using local clock: `next_cycle_start = ceil(utc_now / probe_interval_s) * probe_interval_s`. When the time arrives, issue a `ProbeRequest` with:
   ```go
   probe_id = float64(next_cycle_start)  // e.g., 1727865600.0
   ```
2. **On-Demand (On New Client Join)**:
   - When a client transitions from offline to online (SCTP connection established), start a timer set to `sync_new_client_delay` seconds.
   - If another client connects during this delay, reset the timer.
   - When the timer expires (no new clients connected for `sync_new_client_delay` seconds), issue a `ProbeRequest` with:
     ```go
     probe_id = float64(time.Now().UnixNano()) / 1e9
     if probe_id == math.Floor(probe_id) {  // extremely rare: exact second boundary
         probe_id += 0.001
     }
     // Result: 1727865600.123456789 or 1727865600.001
     ```
   - This mechanism prevents excessive probing when multiple clients join simultaneously.

**Probe ID Properties**:
- Periodic probes always have integer `probe_id` values (e.g., 1727865600.0)
- On-demand probes always have fractional `probe_id` values (e.g., 1727865600.123456789)
- Larger `probe_id` = more recent probe
- The `probe_id` is globally unique and monotonically increasing across all controllers

The controller does NOT track responses to its own `ProbeRequest`. The issuance is fire-and-forget.

**Phase 2: ProbeRequestAck Collection & Statistics** (Triggered by any ProbeRequestAck)
When a controller receives a `ProbeRequestAck` with a `probe_id`:
- If this is the first `ProbeRequestAck` for this `probe_id`, start tracking this probing cycle.
- Begin collecting `AggregatedProbeResult` messages for this `probe_id`.
- This mechanism works identically for all controllers, regardless of who issued the original `ProbeRequest`.
- **Late Arrivals**: Any `AggregatedProbeResult` that arrives after the calculation trigger (see §6.3 step 4) MUST be discarded and logged as late/ignored.

**Constraint**: `sync_new_client_delay` MUST satisfy: `sync_new_client_delay > probe_times * in_probe_interval_ms + probe_timeout_ms + probe_request_timeout` to ensure the on-demand probe cycle can complete before triggering another.

**Client-Side Probing Protocol**:
When a client receives a `ProbeRequest`:
1. **Authoritative Check**: The client checks if the issuing controller is its current authoritative controller.
   - **If not authoritative**: Ignore the `ProbeRequest` entirely. Do not send acknowledgment, do not execute probing.
   - **If authoritative**: Proceed to step 2.
2. **Broadcast Acknowledgment**: The client immediately sends a `ProbeRequestAck` (via SCTP) to **all connected controllers**, containing the same `probe_id`. This allows all controllers (both authoritative and non-authoritative) to track probing progress.
3. **Execute Probing**: The client executes the probing cycle (see execution flow below).

**Probing Execution Flow (OWD Measurement)**:
When a client executes probing (only for requests from the authoritative controller):
- **Transport**: Probe packets (`ProbePing` and `ProbePong`) are transmitted through the encrypted WireGuard connection on `communication_port`. These control messages do not use the RUDP/SCTP reliability layer (probe loss is handled by aggregation logic).
- **Execution**:
  1. For each peer, the client initiates a series of probe pings.
  2. A total of `probe_times` pings are sent, spaced `in_probe_interval_ms` apart. Each ping has a `sub_id` (from 0 to `probe_times - 1`).
  3. **Ping**: Client A sends a `ProbePing` to Peer B containing `{probe_id, sub_id}`. Client A records its local send time for this pair.
  4. **Pong**: Peer B immediately replies with a `ProbePong` containing the same `{probe_id, sub_id}`.
  5. **OWD Calculation**: When Client A receives the pong, it looks up its recorded send time and calculates the one-way delay (OWD) from A to B: `OWD = (receive_time - send_time) / 2` (approximation assuming symmetric path).

### 6.2. Local Aggregation & Upload
- **Result Collection**: After sending all probe pings in a cycle, the client waits for pongs up to `probe_timeout_ms` for each ping.
- **Aggregation**: Once the probing window for the cycle is over (all pings sent and timeout expired), the client aggregates the results for each peer:
  - It calculates the **median OWD** from all successful pong responses.
  - If no responses were received, the OWD is marked as `INF_NUM` (999999).
  - It records the success rate (`successful_probes / probe_times`) for potential future use.
- **Upload**: The client then uploads a single `AggregatedProbeResult` message for the completed cycle (`probe_id`) to **all connected controllers** (via SCTP). This message contains the median OWD and success rate for every peer it probed.

### 6.3. Controller Processing & Path Selection

**Synchronization Barrier (All Controllers - Identical Logic)**:
Every controller performs identical collection and calculation logic, triggered by receiving `ProbeRequestAck` messages:

1. **Cycle Initiation**: When a controller receives the **first** `ProbeRequestAck` for a given `probe_id`, it initializes tracking for this probing cycle:
   - Create a tracking state for this `probe_id`
   - Start a timeout timer: `probe_times * in_probe_interval_ms + probe_timeout_ms + probe_request_timeout`
   - Initialize an empty set to track which clients have submitted results

2. **Ack Collection**: Track which online clients have sent `ProbeRequestAck` for this `probe_id`. Since `ProbeRequestAck` is broadcast to all controllers, every controller receives identical acknowledgments.

3. **Result Collection**: Wait for `AggregatedProbeResult` messages with matching `probe_id` from all acknowledged clients.

4. **Trigger Calculation**: The controller proceeds to routing calculation when:
   - All acknowledged clients have submitted their `AggregatedProbeResult`, OR
   - The timeout expires (whichever comes first)

5. **Broadcast Update**: After calculation, the controller broadcasts a `ControllerStateUpdate` to all connected clients.

**Key Design Points**:
- **ProbeRequest issuance is decoupled**: Controllers issue `ProbeRequest` independently. The issuance does NOT create any tracking state.
- **ProbeRequestAck triggers collection**: The first `ProbeRequestAck` for a `probe_id` initiates the collection phase. All controllers use identical logic.
- **Only authoritative `ProbeRequest` is honored**: Clients ignore `ProbeRequest` from non-authoritative controllers. Only the authoritative controller's request triggers client probing.
- **All controllers synchronize identically**: Since `ProbeRequestAck` is broadcast to all controllers, all controllers observe the same set of responding clients and perform identical calculations.
- **Result**: All controllers maintain consistent state and are ready to become authoritative if needed.

**Edge Weight Selection**:
Before running the graph algorithm, for each pair of directly connected clients (e.g., A to B), the controller must choose a single best path (either v4 or v6) to determine the edge weight. The selection logic is:
1. **Liveness First**: If only one address family path has a finite OWD (< INF_NUM), select that path.
2. **Priority Rules**: If both paths are live:
    a. Select the path corresponding to the address family with the **higher `priority` number** (as announced by the source client A in its `address_families` configuration). Higher priority value = more preferred.
    b. If priorities are equal, select the path with the **lower median OWD**.
3. **Base Latency Addition**: To prevent routing instability due to jitter in low-latency networks (e.g., 2ms ↔ 5ms fluctuations causing unnecessary reroutes), the controller adds `base_latency_ms` to all selected edge weights before running the routing algorithm.

**Directed Graph**: This is a directed graph. The edge weight from A→B and B→A may be different (asymmetric routing is allowed). The controller selects the path for A→B based on client A's `priority` setting, and B→A based on client B's `priority` setting.

**Example Path Selection**:
```
Client A config: v4_priority=10, v6_priority=20
Probe results: A→B via v4: 5ms, A→B via v6: 15ms

Decision: Use v6 path (priority 20 > 10, even though v4 is faster)
Edge weight A→B: 15ms + base_latency_ms
RouteMatrix: When Client A needs to reach Client B's MACs, use Client B's v6_vtep
```

**Path Calculation**:
- The controller uses the computed edge weights to run the **Floyd-Warshall algorithm**, computing the all-pairs shortest path routing table.
- The output `RouteMatrix` is a next-hop lookup table:
  - **Data Structure**: `RouteMatrix[src_pubkey][dst_pubkey] = next_hop_pubkey` (string, the public key of the next hop client)
  - **Unreachable paths**: If no path exists between src and dst, the entry is empty/null/omitted (implementation choice).
  - **Direct connection**: If src can reach dst directly (one hop), `RouteMatrix[src][dst] = dst`.
- The `RouteMatrix` does NOT include latency values or distance metrics. It is purely a forwarding table.
- The routing table is then broadcast in a `ControllerStateUpdate` message to all connected clients.

---

## 7. Client FDB Programming (Decoupled Model)

### 7.1 Local MAC Learning and Monitoring

**Scope**: Only monitor FDB changes on the configured `bridge_name` (from client config). Ignore all other bridges on the system.

**Initialization** (during client startup, after receiving first ControllerStateUpdate):
1. Resolve bridge name to interface index via netlink:
   ```go
   bridge, _ := netlink.LinkByName(config.BridgeName)
   monitorIfIndex := bridge.Attrs().Index
   ```
2. Read existing FDB entries via netlink (RTM_GETNEIGH)
3. Filter criteria - Include only:
   - Entries on `bridge_name` or its slave ports (vxlan-v4, vxlan-v6)
   - NOT matching pattern: `dev {vxlan-v4|vxlan-v6} dst <peer_ip> self permanent`
   - (Exclude controller-installed static entries)
4. Build initial `local_mac_db` from filtered entries

**Runtime Monitoring**:
- Subscribe to netlink RTNLGRP_NEIGH notifications
- Filter incoming events:
  - Only process events where `ifindex` matches `bridge_name` or its slave ports
  - Apply same exclusion rules as initialization (skip `self permanent` entries)
- Debounce timer: `fdb_debounce_ms` (default 500ms, configurable in client config)
  - Accumulate FDB changes within debounce window
  - After timer expires, compute delta and trigger incremental sync
- Trigger incremental MAC sync to all controllers:
  - RTM_NEWNEIGH event → MAC add/update in `LocalMACAnnounce`
  - RTM_DELNEIGH event → MAC remove in `LocalMACAnnounce`

### 7.2 FDB Programming from Authoritative Controller

**Data from Authoritative Controller**: The client only acts upon the `MacOwnership` and `RouteMatrix` datasets from its chosen authoritative controller. Updates from non-authoritative controllers are ignored.

**Client-Side FDB Resolution**: The client combines these two datasets to program its bridge FDB entries:
- For each MAC address in `MacOwnership`, determine which client owns it (e.g., MAC X → Client B with public key `pubkey_B`).
- Look up the path decision in `RouteMatrix[self_pubkey][pubkey_B]`, which returns a `PathSpec` containing `address_family`.
- **If the route is unreachable** (`RouteMatrix[self_pubkey][pubkey_B].address_family == ""`), do NOT program an FDB entry for this MAC. Traffic to this MAC will be dropped or handled by the bridge's default behavior.
- **If reachable** (`address_family == "v4"` or `"v6"`):
  - Look up the owner client's VTEP address from `ClientEndpoints[pubkey_B]`:
    - If `address_family == "v4"`: use `ClientEndpoints[pubkey_B].v4_vtep`
    - If `address_family == "v6"`: use `ClientEndpoints[pubkey_B].v6_vtep`
  - Determine which VXLAN device to use based on `address_family`:
    - `"v4"` → vxlan-v4 device
    - `"v6"` → vxlan-v6 device
  - Program the bridge FDB entry using netlink

**FDB Programming Implementation**:
```go
func applyFDBEntry(mac string, ownerPubKey string) error {
    pathSpec := routeMatrix[selfPubKey][ownerPubKey]
    clientInfo := clientEndpoints[ownerPubKey]

    hwAddr, _ := net.ParseMAC(mac)

    switch pathSpec.AddressFamily {
    case "v4":
        if clientInfo.V4VTEP == "" {
            log.Warn("v4 path selected but no v4_vtep available")
            return nil
        }
        targetLink, _ := netlink.LinkByName("vxlan-v4")
        targetIP := net.ParseIP(clientInfo.V4VTEP)

        // Remove from v6 device if exists
        v6Link, _ := netlink.LinkByName("vxlan-v6")
        netlink.NeighDel(&netlink.Neigh{
            LinkIndex:    v6Link.Attrs().Index,
            HardwareAddr: hwAddr,
        })

        // Add to v4 device
        return netlink.NeighSet(&netlink.Neigh{
            LinkIndex:    targetLink.Attrs().Index,
            State:        netlink.NUD_PERMANENT,
            Family:       unix.AF_BRIDGE,
            Flags:        netlink.NTF_SELF,
            HardwareAddr: hwAddr,
            IP:           targetIP,
        })

    case "v6":
        if clientInfo.V6VTEP == "" {
            log.Warn("v6 path selected but no v6_vtep available")
            return nil
        }
        targetLink, _ := netlink.LinkByName("vxlan-v6")
        targetIP := net.ParseIP(clientInfo.V6VTEP)

        // Remove from v4 device if exists
        v4Link, _ := netlink.LinkByName("vxlan-v4")
        netlink.NeighDel(&netlink.Neigh{
            LinkIndex:    v4Link.Attrs().Index,
            HardwareAddr: hwAddr,
        })

        // Add to v6 device
        return netlink.NeighSet(&netlink.Neigh{
            LinkIndex:    targetLink.Attrs().Index,
            State:        netlink.NUD_PERMANENT,
            Family:       unix.AF_BRIDGE,
            Flags:        netlink.NTF_SELF,
            HardwareAddr: hwAddr,
            IP:           targetIP,
        })

    case "":  // Unreachable
        // Remove from both devices
        for _, devName := range []string{"vxlan-v4", "vxlan-v6"} {
            link, _ := netlink.LinkByName(devName)
            netlink.NeighDel(&netlink.Neigh{
                LinkIndex:    link.Attrs().Index,
                HardwareAddr: hwAddr,
            })
        }
        return nil
    }
}
```

**FDB Entry Flags**:
- `NTF_SELF`: Entry is for the VXLAN device itself (not bridge port)
- `NUD_PERMANENT`: Entry is static, won't age out
- These flags ensure the entry is distinct from dynamically learned MACs

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
- `client_offline_timeout`: Duration in seconds to wait for a disconnected client to reconnect before removing its MAC entries and recomputing routes (default: 300).
- `sync_new_client_delay`: Duration in seconds to wait after a new client connects before triggering a `ProbeRequest`. The timer resets if another client connects during this period (default: 5). Must satisfy: `sync_new_client_delay > probe_times * in_probe_interval_ms + probe_timeout_ms + probe_request_timeout`.
- `probe_request_timeout`: Duration in milliseconds to wait for `AggregatedProbeResult` after the probing window closes (default: 1000). Total wait time for all results is: `probe_times * in_probe_interval_ms + probe_timeout_ms + probe_request_timeout`.
- `vxlan`: `{ "vni": 100, "port": 4789, "mtu": 1450 }`
- `probing`:
    - `probe_interval_s`: 60
    - `probe_times`: 5
    - `in_probe_interval_ms`: 200
    - `probe_timeout_ms`: 1000
    - **Constraint**: The operator must ensure timings allow for completion within a cycle. A valid configuration must satisfy: `probe_times * in_probe_interval_ms + probe_timeout_ms < (probe_interval_s - 1) * 1000`.
- `routing`:
  - `static_weight`: `false` to use dynamic probing, `true` to use static latency matrix
  - `base_latency_ms`: `100` (added to all edge weights to prevent jitter-induced instability)
  - `static_latency_ms`: An n×n matrix of latency values (in milliseconds) representing directed edges between clients, where n is the number of clients. The entry at row i, column j represents the latency from client i to client j. Use `999999` (hardcoded constant `INF_NUM`) to represent unreachable/disconnected paths (as JSON does not support infinity). Client indices are assigned based on sorted public keys.

### Client (`client.conf`)
- `private_key`: The client's private key.
- `bridge_name`: The Linux bridge name to monitor for FDB changes (e.g., "br-vxlan"). Only FDB events on this bridge and its slave ports will be processed.
- `communication_port`: UDP port for WireGuard encrypted control plane traffic.
- `clamp_mss_to_mtu`: `true` or `false`.
- `init_timeout`: Duration in seconds to wait during initialization mode before selecting the authoritative controller and programming FDB entries (default: 10). This allows all controllers to stabilize their `client_count` and `last_client_change_timestamp` before the client commits to an authoritative selection.
- `fdb_debounce_ms`: Debounce time in milliseconds for FDB change events (default: 500). FDB changes within this window are batched together before triggering MAC synchronization to controllers.
- `address_families`:
  - `v4`: `{ "vxlan_name": "vxlan-v4", "bind_addr": "0.0.0.0", "priority": 10 }`
    - `priority`: Higher value = more preferred. Used by controller to select optimal path.
  - `v6`: `{ "vxlan_name": "vxlan-v6", "bind_addr": "::", "priority": 20 }`
- `controllers`: An array of controller connection info.
  ```json
  [
    {"public_key": "CONTROLLER_PUBKEY_1", "address_v4": "1.1.1.1:7890", "address_v6": "[2001::1]:7890"},
    {"public_key": "CONTROLLER_PUBKEY_2", "address_v4": "2.2.2.2:7890", "address_v6": "[2001::2]:7890"}
  ]
  ```
- `ntp_servers`: An array of NTP server addresses.
