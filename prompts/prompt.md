# VXLAN Controller + Client

You are an expert Linux networking engineer and systems programmer. Implement a minimal but production-grade **EVPN-like VXLAN controller and client** in Go. Your implementation will use Linux netlink to manage VXLAN devices and the bridge FDB. The primary design goals are correctness, stability, and operational robustness.

---

## 1. Security & Identity
- **Authentication**: Mutual authentication is performed using WireGuard-style static public/private keys.
- **Client Identity**: A client's identity is its **public key**. The controllers maintain an clientlist.
- **Transport Security**:
  - **Control Plane Encryption (Client-Controller & Client-Client Control Messages)**: All control plane communication MUST be encrypted using WireGuard-style cryptography (X25519 key exchange, ChaCha20-Poly1305 AEAD). A peer is identified by its public key. This includes:
    - Client-Controller RPC messages (with userspace TCP-like stream socket reliability layer)
    - Client-Client probe packets (ClientProbeRequest/ClientProbeResponse)
  - **Data Plane (VXLAN)**: VXLAN packets carrying actual network traffic are transmitted as **plain UDP packets without encryption**. These are sent to peers' VXLAN endpoints independently of the WireGuard encryption layer.
  - **Reliability Layer (Client-Controller Only)**: For client-controller communication, a **userspace-implemented TCP-like stream socket** is layered on top of the encryption layer to ensure message integrity and ordered delivery for control plane messages. The stream socket layer must provide TCP-like semantics including retransmission, checksums, packet reordering, connection timeout detection, fast recovery, PAWS, MSS negotiation, congestion control, etc. This is implemented in userspace, not using kernel TCP or SCTP.

#### Stream Socket Implementation Details

**Initialization & API Design**:
- **NewListener(datagram, mss)**: Creates a traditional TCP-like listener. Returns a `StreamListener` interface.
- **NewListenerChan(datagram, mss)**: Creates a channel-based listener. Returns a channel that receives events and data.
- **NewConnection(datagram, mss)**: Creates a client connection using socket mode. Returns a `StreamSocket` interface or error.
- **NewConnectionChan(datagram, mss)**: Creates a client connection using channel mode. Returns event/data channels.
- **Datagram Socket Type**: In this project, the `datagram` parameter MUST be a `PeerSocket` returned by the WireGuard-like encryption layer (§1.1.1). The stream socket layer operates on top of the encrypted datagram transport.
- **Datagram Socket Lifecycle**: The underlying `PeerSocket` remains open for the lifetime of the encryption layer peer entry. The stream socket layer does not close the datagram socket; it only manages stream-level connection state on top of the persistent encrypted channel.
- **Constraint**: One datagram socket can handle exactly **one** stream socket connection. Multiple connection attempts to the same listener will close the previous socket and trigger reconnection events.

**Socket Mode (Traditional TCP-like)**:
```go
type StreamListener interface {
    Accept() (StreamSocket, error)  // Blocks until client connects
    Close() error
}

type StreamSocket interface {
    Read(buf []byte) (int, error)   // Blocks until data available
    Write(data []byte) (int, error) // Blocks until data sent
    Close() error
}
```

**Channel Mode (Event-driven)**:
```go
type StreamEvent struct {
    Type StreamEventType
    Data []byte  // Contains data for DataReceived events
    Error error  // Contains error details for Error events
}

type StreamEventType int
const (
    EventConnected StreamEventType = iota
    EventDisconnected  // Network quality issues, can reconnect
    EventDataReceived  // Data field contains received bytes
    EventError        // Underlying socket issues, cannot recover
)

// Channel mode APIs
func NewListenerChan(datagram PeerSocket, mss int) (<-chan StreamEvent, chan<- []byte, error)
func NewConnectionChan(datagram PeerSocket, mss int) (<-chan StreamEvent, chan<- []byte, error)
```

**Event Classification**:

**EventDisconnected** (Network Quality Issues - Recoverable):
- **Excessive Packet Loss**: Too many retransmissions without acknowledgment
- **Connection Timeout**: No response within configured timeout periods
- **Synchronization Loss**: Sequence number or state machine errors due to packet loss/reordering
- **Peer Closure**: Remote peer explicitly closes the connection
- **New Connection Replacement**: Same datagram receives new connection request
- **Recovery**: Can attempt reconnection, automatic reconnection in channel mode

**EventError** (Underlying Socket Issues - Non-recoverable):
- **Datagram Socket Closed**: The underlying PeerSocket was closed
- **Permission Denied**: No permission to use the underlying socket
- **Socket Failure**: Other fundamental socket errors from the datagram layer
- **Recovery**: Cannot recover automatically, requires application-level intervention

**Channel Mode Connection Behavior**:
- **Persistent Channel**: The event channel never closes unless `EventError` occurs.
- **Non-blocking Writes**: Writing to the write channel is non-blocking. Data is queued for transmission and sent when connection is available.
- **Write Behavior When Disconnected**: Packets written to the write channel are **silently discarded** when connection state is not connected.
- **Timeout Detection**: If queued writes timeout due to network issues, it triggers `EventDisconnected` asynchronously (not immediately during write).
- **Automatic Reconnection**: Client automatically attempts to reconnect after `EventDisconnected`, triggering new `EventConnected` when successful.
- **Error Handling**: `EventError` terminates the stream socket permanently. Application must create new stream socket with new datagram.
- **Connection Lifecycle**: `Connected -> DataReceived... -> Disconnected -> Connected -> DataReceived... -> Error (terminal)`
- **Timeout Management**: Connections have configurable timeouts similar to TCP socket timeouts.

**Connection Lifecycle**:
1. **Server Side (Socket Mode)**: `Accept()` blocks until client connects. `EventDisconnected` causes connection closure but listener remains active. `EventError` closes listener.
2. **Server Side (Channel Mode)**: Event channel receives `EventConnected`/`EventDisconnected` for network issues. `EventError` terminates the entire listener.
3. **Client Side (Socket Mode)**: `EventDisconnected` closes socket but allows new connection attempts. `EventError` prevents further use.
4. **Client Side (Channel Mode)**: `EventDisconnected` triggers automatic reconnection. `EventError` terminates stream socket permanently.
5. **Error Details**: Both `EventDisconnected` and `EventError` include specific error information for logging and debugging.

**MSS Negotiation & Probing**:
- **Handshake MSS Exchange**: During connection establishment, both peers exchange their configured MSS values (from controller/client configuration).
- **Effective MSS**: The smaller of the two MSS values is used for actual packet transmission.
- **MSS Probing (when either side has MSS=0)**:
  - If either peer's MSS is 0, automatic MSS probing is triggered.
  - The connector initiates MSS probing using **Galloping Search** starting from 1400 bytes.
  - Probe packets are sent with increasing sizes: 1400, 1450, 1500, etc.
  - The listener responds with the same size to confirm successful delivery.
  - The largest successfully transmitted size becomes the effective MSS.
  - Probing continues until packet loss occurs or a maximum threshold is reached.
  - The probed MSS is cached and reused for the lifetime of the listener/connector instance.
  - **Synchronization Strategy**: Under normal operation, incremental (delta) updates are used to minimize bandwidth. When inconsistency is detected (corrupted state, or after reconnection), a full state synchronization MUST be triggered.
  - **Reconnection**: When the stream socket layer reports a socket closure or timeout (indicating loss of communication), the client MUST immediately reconnect, perform a FullUpload (resubmit complete local state including MAC table), and execute a FullDownload (request full snapshot from controller).

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
    NewPeerSockMode(pubKey PublicKey, remoteAddr *net.IP, remotePort int, roamingMode RoamingMode, enableEventChannel bool) (PeerSocket, <-chan RoamingEvent, error)
    NewPeerChainMode(pubKey PublicKey, remoteAddr *net.IP, remotePort int, roamingMode RoamingMode, enableEventChannel bool) (chan []byte, chan []byte, <-chan RoamingEvent, error)

    // Endpoint Management
    GetLocalEndpoint() *Endpoint  // Returns this instance's bind_addr:communication_port
    SetPeerEndpoint(pubKey PublicKey, addr net.IP, port int) error
    GetPeerEndpoint(pubKey PublicKey) *Endpoint

    // Lifecycle
    Close() error
}

type RoamingEvent struct {
    PeerPublicKey PublicKey
    OldEndpoint   *Endpoint  // Previous IP:port, nil if first connection
    NewEndpoint   *Endpoint  // New IP:port
    Timestamp     time.Time
}

type Endpoint struct {
    IP   net.IP
    Port int
}

type PeerSocket interface {
    // Datagram operations
    Send(data []byte) error  // Non-blocking, queues data for transmission
    Recv() ([]byte, error)   // Blocks until data available

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
- **Non-blocking Writes**: Writing to a `PeerSocket` is non-blocking and queues data for transmission. The EncryptionLayer handles encryption and UDP transmission asynchronously.
- **Blocking Reads**: Reading from a `PeerSocket` blocks until data is available and returns decrypted data received from that peer.
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
- The encryption layer does not guarantee delivery; reliability is layered above (userspace TCP-like stream socket for control plane).

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
  - **Client-Client**: Client-client peer registration is driven entirely by `ControllerStateUpdate.ClientEndpoints` data from the authoritative controller:
    - **Initial Registration**: For each peer public key in `ClientEndpoints`, call `NewPeer(pubkey, null, 0, disabled)` to create the peer entry with no initial endpoint. When the client connect, it will roaming to it just like wireguard and trigger the event.
    - **Endpoint Configuration**: Immediately call `SetPeerEndpoint(pubkey, addr, port)` using the controller-provided endpoint from `ClientEndpoints[pubkey]`
    - **Dynamic Updates**: When receiving updated `ControllerStateUpdate` messages, call `SetPeerEndpoint()` for any changed peer endpoints
    - **Address Family Selection**: Use the peer's v4 or v6 endpoint based on the client's own address family configuration and availability
- **Network Environment Assumption**: This design assumes all nodes have publicly reachable IP addresses (no NAT). Double-NAT scenarios where both peers have `remote_addr = null` are not supported, as neither peer can initiate the first packet.
- Registration returns a datagram-capable socket handle that higher layers use for messaging.

**Endpoint Update & Roaming**:
- The layer exposes APIs to update a peer's endpoint explicitly (`SetPeerEndpoint`). Controllers use this to push authoritative endpoint changes.
- **Roaming Event Channel**: 
  - **Controllers**: Always use `enableEventChannel = true` to receive real-time endpoint change notifications. Controllers must detect client roaming immediately and broadcast updates to all clients via `ControllerStateUpdate`.
  - **Clients**: Always use `enableEventChannel = false` since they only accept endpoint information from controller broadcasts, not from direct peer roaming detection.
- **Event Delivery**: The roaming event channel delivers events when the layer accepts an endpoint change from an authenticated packet (subject to the peer's `roamingMode` setting).
- Endpoint inspection APIs (`GetPeerEndpoint`) let higher layers retrieve the currently active remote address/port pair for any peer.
- Supported roaming behaviors are chosen per peer:
  - **`disabled`**: Authenticated packets from new source addresses are processed, but the stored endpoint is never updated automatically.
  - **`same_af`**: The endpoint is updated only if the new source IP has the same address family as the currently stored endpoint.
  - **`all`**: The endpoint is always updated to the new source IP:port, regardless of address family. Requires both `bind_addr_v4` and `bind_addr_v6` to be set.
- When a legitimate endpoint change is accepted (via roaming or explicit API), the controller receives a `RoamingEvent` on the event channel (if enabled) and must update `last_client_change_timestamp` and broadcast the updated endpoint so all clients stay aligned (§2.1).

**Socket Handle Lifecycle**:
- The socket handle behaves like UDP for sending/receiving. Reliability and ordering (userspace-implemented TCP-like stream socket) are layered above when required.
- **Persistent Peer Entries**: Peer entries are persistent and stateless. The encryption layer does NOT maintain "connection" state.
  - Peer sockets never "disconnect" or "timeout" on their own.
  - The encryption layer automatically manages WireGuard handshakes and rekeying transparently.
  - Handshake failures, packet loss, or cryptographic errors do not affect peer persistence.
  - The layer will continuously retry handshakes with exponential backoff when needed.
- **No Automatic Cleanup**: The encryption layer NEVER automatically removes peer entries. Peers persist indefinitely until explicitly removed.
  - Controllers never call `Close()` on peer sockets. A client's peer entry (identified by its unique public key) exists for the lifetime of the controller process.
  - Clients only call `Close()` when permanently removing a peer (e.g., peer deleted from network configuration).
- **Lifecycle Management Responsibility**:
  - The stream socket layer (built on top of encryption layer) is responsible for detecting connection timeouts and notifying the application layer.
  - Application layer decides when to close peer sockets based on higher-level logic (not encryption layer failures).
- **Thread Safety**: `Close()` on a `PeerSocket` is thread-safe. Any packets received after `Close()` are silently dropped.
- The public key remains the stable identifier for the peer throughout its lifecycle.

#### 1.1.4 Traffic Flow
- **Control Plane (Client-Controller)**: RPC messages are encrypted by the WireGuard layer, with userspace TCP-like stream socket providing reliability on top of the encrypted channel.
- **Data Plane (Client-Client VXLAN)**: VXLAN packets carrying actual network traffic are transmitted as **plain UDP packets without encryption**. These packets are sent directly to the peer's VXLAN endpoint (UDP port configured in `vxlan.port`), bypassing the WireGuard encryption layer entirely.
- **Probing Packets (Client-Client)**: ClientProbeRequest/ClientProbeResponse messages are sent through the encrypted WireGuard connection. These are control messages but do not require stream socket reliability (probe loss is handled by aggregation logic).
- The WireGuard encryption layer multiplexes handshake packets (`type 1, 2`) and data packets (`type 4`) on the same UDP socket (using `communication_port`).
- Upper layers simply read/write plaintext; encryption/decryption and handshake management are fully encapsulated.

---

## 2. Control Plane Protocol & Multi-Controller Architecture
Clients connect to **all configured controllers simultaneously**. An RPC-style protocol over a userspace-implemented TCP-like stream socket transport is used. Messages should be serialized using **Protocol Buffers or Go's `gob`**.

- **Controller State Broadcast**: State update messages from a controller **must include**:
  - **Status**: `client_count`, `last_client_change_timestamp` (Unix timestamp when the stream socket layer last detected a connection state change: new connection establishment, disconnection, or timeout).
  - **Configuration**: `vxlan` settings, `probing` parameters, `routing` parameters (including `base_latency_ms`).
  - **Network View**: Contains updates for the controller's three authoritative datasets and is delivered as either a full snapshot or a delta from the previous update:
    1. `ClientEndpoints`: public IPv4/IPv6 endpoints for every registered client.
    2. `MacOwnership`: MAC address inventory mapped to the client that announced each MAC.
    3. `RouteMatrix`: the Floyd-Warshall result describing the computed all-pairs shortest paths between clients. Data structure: `RouteMatrix[src][dst] = next_hop_client_and_address_family` or empty/null (if unreachable). Does NOT contain latency information, only next hop routing decisions.
- **Message Types**:
  - `ControllerStateRequest`: Client requests network state from a controller. Controllers ALWAYS respond with a full snapshot of all three datasets. Clients MUST issue this request at startup, immediately after any stream socket reconnect event, and whenever their authoritative controller changes.
  - `ControllerStateUpdate`: Broadcast from a controller containing its status, configuration, and network view (all three datasets). Can be either:
    - **Full Snapshot** (`update_mode = "full"`): Complete state of all three datasets (always sent in response to `ControllerStateRequest`)
    - **Delta Update** (`update_mode = "diff"`): Incremental changes since the last update (proactively pushed by controller when state changes)
    - **Message Structure**:
      ```protobuf
      message ControllerStateUpdate {
          string update_mode = 1;  // "full" or "diff"
          ControllerStatus status = 2;
          NetworkConfig config = 3;
          ClientEndpointsMap client_endpoints = 4;
          MacOwnershipMap mac_ownership = 5;
          RouteMatrixMap route_matrix = 6;
      }

      message ClientEndpointsMap {
          // key: client public_key
          map<string, ClientEndpoint> endpoints = 1;
      }

      message ClientEndpoint {
          optional fixed32 v4_ip = 1;
          optional fixed32 v4_port = 2;
          optional bytes v6_ip = 3;
          optional fixed32 v6_port = 4;
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
          sfixed32 address_family = 1;  // 0 (unreachable) | 4 (ipv4) | 6 (ipv6)
          string next_hop_client_pubkey = 2;
          // Example: RouteMatrix[A][B] = {client_pubkey, address_family: "v6"}
          // Means: Client A should use Client B's v6_ip to reach B
      }
      ```
  - `ControllerProbeRequest`: Issued by any controller to trigger a probing cycle. Contains a unique `probe_id`. Clients only execute probing if the request comes from their authoritative controller; non-authoritative `ControllerProbeRequest` messages are ignored.
    ```protobuf
    message ControllerProbeRequest {
        double probe_id = 1;
    }
    ```
  - `ControllerProbeRequestAck`: Client responds to `ControllerProbeRequest` from its authoritative controller. Contains the same `probe_id`. This acknowledgment is sent to **all connected controllers** (not just the issuing controller).
  - `ProbeResult`: Client uploads its aggregated OWD measurements for a completed cycle to all controllers. Contains `probe_id` and per-peer path metrics.
  - `MulticastPacket`: Client forwards captured multicast/broadcast packets to its authoritative controller. Contains the raw Ethernet frame.
    ```protobuf
    message MulticastPacket {
        string source_client_id = 1;      // client public key
        bytes ethernet_frame = 2;          // complete L2 frame including dst/src MAC, ethertype, payload
        int64 capture_timestamp = 3;       // Unix timestamp when packet was captured
    }
    ```
  - `MulticastForward`: Controller broadcasts multicast packets to all other clients (except the source). Clients inject these packets into their local bridge using raw sockets. This message is processed by **all clients** regardless of authoritative controller selection.
    ```protobuf
    message MulticastForward {
        string source_client_id = 1;      // original sender's public key
        bytes ethernet_frame = 2;          // complete L2 frame to inject
        int64 controller_timestamp = 3;    // Unix timestamp when controller forwarded
    }
    ```
    ```protobuf
    message ProbeResult {
        double probe_id = 1;
        string source_client_id = 2;
        map<string, PeerMetrics> path_metrics = 3;  // key: target client public_key
    }

    message PeerMetrics {
        double v4_latency_ms = 1;  // INF_NUM if unreachable
        double v6_latency_ms = 2;  // INF_NUM if unreachable
        bool v4_reachable = 3;
        bool v6_reachable = 4;
        int32 v4_priority = 5;  // client's v4 priority
        int32 v6_priority = 6;  // client's v6 priority
    }
    ```
  - `LocalMACAnnounce`: Client announces its local MAC addresses to all controllers. Each MAC entry includes a `learned_timestamp` (Unix timestamp when the MAC was learned/updated by the client). Can be either:
    - **Full Announcement** (`announce_mode = "full"`): Complete MAC table (sent during FullUpload)
    - **Delta Announcement** (`announce_mode = "diff"`): Only changed MACs (sent when local bridge FDB changes, supports both add and remove operations)
    - **Message Structure**:
      ```protobuf
      message LocalMACAnnounce {
          string announce_mode = 1;  // "full" or "diff"
          string client_id = 2;      // client public key
          repeated MACEntry mac_entries = 3;
      }

      message MACEntry {
          string mac_address = 1;
          int64 learned_timestamp = 2;  // Unix timestamp
          sfixed32 operation = 0 (add) | 1 (update) | 2 (remove); ( 2 and 3 only used in diff mode)
      }
      ```
  - **FullUpload**: A client-side operation that resends its complete local state. Implemented as a full `LocalMACAnnounce` (containing all current MACs).
  - **FullDownload**: A client-side operation that requests and applies a full controller snapshot (`ControllerStateRequest` + full `ControllerStateUpdate` response).

### 2.2. Incremental Push Implementation

**Controller-Side State Management**:

The controller maintains the following databases:
1. **Per-Client MAC Database** (`client_mac_db`): `map[client_pubkey]map[mac_address]learned_timestamp`
   - Stores each client's complete MAC table separately
   - Updated when receiving `LocalMACAnnounce` messages

2. **Global MAC Ownership Database** (`MacOwnership`): `map[mac_address]ClientMACInfo`
   - Merged view of all MAC addresses and their owners
   - Structure: `ClientMACInfo { client_pubkey, learned_timestamp }`
   - This is the authoritative MAC ownership table

3. **Previous MAC Ownership Snapshot** (`OldMacOwnership`): `map[mac_address]ClientMACInfo`
   - Copy of the previous `MacOwnership` state
   - Used to compute diffs for incremental updates

**Controller Processing Flow (MAC Updates)**:

When a controller receives `LocalMACAnnounce`:

1. **Update Per-Client Database**:
   - If `announce_mode = "full"`: Replace `client_mac_db[client_pubkey]` with the uploaded MAC table
   - If `announce_mode = "diff"`: Apply incremental changes to `client_mac_db[client_pubkey]`:
     - For each entry with `operation = "add"`: Insert/update MAC in client's table
     - For each entry with `operation = "remove"`: Delete MAC from client's table

2. **Merge to Global MacOwnership**:
   - For each MAC in the updated `client_mac_db[client_pubkey]`:
     - If MAC doesn't exist in `MacOwnership`: Add it with `{ client_pubkey, learned_timestamp }`
     - If MAC exists in `MacOwnership`: Compare `learned_timestamp`:
       - If new timestamp is newer (higher value): Update ownership to new client
       - If timestamps are equal: Keep the most recently received announcement (last-write-wins)
   - For removed MACs (only in diff mode): Delete from `MacOwnership` if currently owned by this client

3. **Compute Diff**:
   - Compare current `MacOwnership` with `OldMacOwnership`
   - Build delta containing:
     - Added MACs: In `MacOwnership` but not in `OldMacOwnership`
     - Removed MACs: In `OldMacOwnership` but not in `MacOwnership`
     - Changed MACs: In both but with different owner or timestamp

4. **Update Snapshot**:
   - Copy current `MacOwnership` to `OldMacOwnership`

5. **Broadcast Update**:
   - Send `ControllerStateUpdate` with `update_mode = "diff"` containing only the delta
   - Include updated `last_client_change_timestamp` if connection state changed
   - Broadcast to all connected clients

**Client-Side State Management**:

The client maintains:
1. **Per-Controller State** (`controller_states`): `map[controller_pubkey]ControllerState`
   - Separate state snapshot for each connected controller
   - Structure:
     ```go
     type ControllerState {
         ClientEndpoints map[client_pubkey]ClientEndpoint
         MacOwnership    map[mac_address]ClientMACInfo
         RouteMatrix     map[src_pubkey]map[dst_pubkey]PathSpec
         Status          ControllerStatus
         Config          NetworkConfig
         Synced          bool  // true only after receiving update_mode="full"
     }
     ```

2. **Authoritative Controller Selection**: Public key of the currently selected authoritative controller

**Client Processing Flow (Controller Updates)**:

When a client receives `ControllerStateUpdate` from a controller:

1. **Check Synchronization State**:
   - If `update_mode = "diff"` and `controller_states[controller_pubkey].Synced == false`:
     - **Ignore the update completely** (log and discard)
     - Return immediately (do not process)
   - If `update_mode = "full"`:
     - Proceed to step 2

2. **Apply Update to Controller State**:
   - If `update_mode = "full"`:
     - Replace entire `controller_states[controller_pubkey]` with received data
     - Mark `Synced = true` for this controller
   - If `update_mode = "diff"` (only processed if `Synced == true`):
     - Apply incremental changes to `controller_states[controller_pubkey]`:
       - **ClientEndpoints**: Merge/update/delete entries as specified in delta
       - **MacOwnership**: Apply MAC additions/removals/changes
       - **RouteMatrix**: Apply routing table updates
     - Keep `Synced = true` (already synchronized)

3. **Re-evaluate Authoritative Controller**:
   - Run the selection algorithm (§3) across all controllers where `Synced == true`
   - Controllers with `Synced == false` are excluded from selection
   - Determine if the authoritative controller has changed

4. **Synchronize to Local State** (Only if this is the authoritative controller):
   - **Update Peer Endpoints**: For each peer in `ClientEndpoints`, call `SetPeerEndpoint` on the encryption layer
   - **Update FDB Table**: Reprogram bridge FDB entries based on `MacOwnership` and `RouteMatrix` (§7.2)

### Full State Synchronization Workflows
- **FullUpload**
  - Triggered during initial startup and after any stream socket reconnect.
  - The client compiles its authoritative local data set: every locally owned MAC address from the bridge FDB.
  - This data is sent to the reconnected controller via `LocalMACAnnounce` with `announce_mode = "full"`.
  - Controllers treat the full upload as canonical, replace their stored state for that client in `client_mac_db`, merge to `MacOwnership`, compute diff with `OldMacOwnership`, update `last_client_change_timestamp` (due to stream socket reconnection event), and broadcast `ControllerStateUpdate` to all clients.
- **FullDownload**
  - Triggered during initial startup and after any stream socket reconnect.
  - Before issuing `ControllerStateRequest`, the client marks `controller_states[controller_pubkey].Synced = false` for that controller.
  - The client issues a `ControllerStateRequest` and waits for the matching `ControllerStateUpdate` with `update_mode = "full"` containing all three datasets (ClientEndpoints, MacOwnership, RouteMatrix).
  - After receipt, the client replaces the controller's state snapshot in `controller_states`, marks `Synced = true`, re-evaluates authoritative controller selection if necessary, and reprograms its peer endpoints and FDB tables if this is the authoritative controller or authoritative controller changes.
  - While `Synced = false`, all `ControllerStateUpdate` messages with `update_mode = "diff"` from that controller are ignored.

### 2.1. Client State Management & Multi-Controller Synchronization

**Client-Side Controller State Tracking**:
- The client maintains a **separate state snapshot** for each connected controller.
- Each controller's state includes: `ClientEndpoints`, `MacOwnership`, `RouteMatrix`, and configuration parameters.
- The client continuously updates each controller's state snapshot when receiving `ControllerStateUpdate` messages from that controller.
- The client does NOT notify controllers when changing its authoritative controller selection. The authoritative selection is a local decision.

**Initialization Protocol**:
1. **Connection Phase**: The client connects to all configured controllers and immediately starts the `init_timeout` timer.
2. **Initialize Sync State**: For each controller, initialize `controller_states[controller_pubkey].Synced = false`.
3. **FDB Monitoring Initialization**: The client starts monitoring FDB changes on the configured `bridge_name` via netlink (RTNLGRP_NEIGH) and begins buffering FDB change events.
4. **Local MAC Discovery**: The client reads the current FDB snapshot from the bridge to build `local_mac_db`:
   - Use netlink RTM_GETNEIGH to query FDB entries
   - Filter: Only entries on `bridge_name` and its slave ports
   - Exclude: Entries on controller-managed VXLAN devices (vxlan-v4, vxlan-v6) which contain remote MAC addresses programmed by the controller
   - Exclude: Entries matching pattern `dev <controller-managed vxlan device> dst <peer_ip> self permanent` (controller-installed static FDB entries for remote nodes)
   - Include: All other slave ports including physical interfaces (eth0), virtual interfaces (tap0, veth), and user-created VXLAN devices
   - Build initial `local_mac_db` from filtered entries (these represent locally owned MACs)
   - Keep `local_mac_db` synchronized with the bridge by processing buffered and incoming FDB change events
5. **FullUpload Phase**: The client uploads its complete `local_mac_db` (full MAC table with `learned_timestamp`) to **all** controllers.
6. **FullDownload Phase**: The client issues `ControllerStateRequest` to **all** controllers.
7. **Wait for Controller Responses**: The client waits for `ControllerStateUpdate` responses in **initialization mode**:
   - When receiving `update_mode = "full"`: Update that controller's state snapshot and mark `Synced = true`.
   - When receiving `update_mode = "diff"`: Ignore (since `Synced = false` for all controllers initially).
   - The client continuously re-evaluates the authoritative controller selection algorithm (§3) across controllers where `Synced = true`, but does NOT yet apply any FDB or peer endpoint programming.
   - The client ignores any `ControllerProbeRequest` messages during initialization (does not execute probing).
   - Continue processing and buffering local FDB changes to keep `local_mac_db` up to date.
8. **Exit Initialization Mode**: The client exits initialization mode when:
   - All controllers have sent their initial `ControllerStateUpdate` with `update_mode = "full"` (all `Synced = true`), OR
   - The `init_timeout` expires (whichever comes first)
9. **Initialization Success Check**:
   - If **at least one** controller has `Synced = true`, proceed to step 10.
   - If **all controllers** have `Synced = false` (no full updates received), the client logs a critical error and terminates.
10. **Apply Network Configuration**: The client selects the authoritative controller from controllers where `Synced = true` (using the algorithm in §3) and synchronizes to local state:
   - **Update Peer Endpoints**: For each peer in `ClientEndpoints`, call `SetPeerEndpoint` on the encryption layer
   - **Update FDB Table**: Program bridge FDB entries based on `MacOwnership` and `RouteMatrix` (§7.2)
11. **Process Buffered FDB Events**: The client processes all buffered FDB change events accumulated during initialization as incremental updates, sending `LocalMACAnnounce` with `announce_mode = "diff"` to all controllers.
12. **Begin Normal Operation**: The client begins accepting and executing `ControllerProbeRequest` messages from its authoritative controller.

**Rationale**: During startup, `client_count` and `last_client_change_timestamp` may fluctuate rapidly as clients connect. The `init_timeout` prevents premature FDB programming and allows the client to wait for a stable authoritative controller selection.

**Stream Socket Layer Semantics**:
- The stream socket layer MUST behave like TCP: it provides reliable, ordered delivery with retransmission, checksums, packet reordering, and timeout detection.
- The stream socket layer operates independently of the underlying UDP encryption layer. Transient UDP failures (disconnection/reconnection) that recover within the stream socket timeout period will trigger retransmissions but will NOT cause stream socket connection failure.
- When the stream socket detects an unrecoverable error (timeout after all retries exhausted), it closes the connection and reports an error to the application layer. The peer's stream socket should also close the connection.

**Client-Side Reconnection Protocol**:
When the client's stream socket layer reports connection failure for a specific controller:
1. Close the stream socket connection to that controller
2. Mark `controller_states[controller_pubkey].Synced = false` for that controller
3. Re-evaluate authoritative controller selection (§3) across remaining controllers where `Synced = true`
   - If the disconnected controller was authoritative and another synchronized controller is available, switch to it and reprogram FDB
   - If the disconnected controller was authoritative and no other synchronized controllers exist, the client has no authoritative controller until reconnection succeeds
4. Re-establish a new stream socket connection to the controller
5. Perform a FullUpload to resubmit complete local state (full MAC table with `learned_timestamp` for each MAC)
6. Issue a `ControllerStateRequest` to perform a FullDownload
7. When the full `ControllerStateUpdate` with `update_mode = "full"` is received, update that controller's state snapshot and mark `Synced = true`
8. Re-evaluate authoritative controller selection (§3) across all controllers where `Synced = true`
9. If the authoritative controller changed, reprogram FDB entries using the new authoritative controller's state
10. While `Synced = false`, all `ControllerStateUpdate` messages with `update_mode = "diff"` from that controller are ignored

**Controller-Side Connection Handling**:
- When the controller's stream socket layer detects a client connection failure, the controller marks the client as offline, updates `last_client_change_timestamp`, and waits for the client to reconnect.
- If the client reconnects, the controller accepts the new stream socket connection. If the client had an existing (but failed) stream socket session, the controller closes the old session and replaces it with the new one.
- If the client does NOT reconnect within a configurable timeout (`client_offline_timeout`), the controller:
  1. Deletes all MAC addresses owned by that client from `MacOwnership`
  2. Recomputes the `RouteMatrix` (excluding the offline client)
  3. Broadcasts a `ControllerStateUpdate` to all remaining clients

**Authoritative Controller Change (After Initialization)**:
- When the authoritative controller changes (detected via the selection algorithm in §3), the client silently switches to using the new authoritative controller's state snapshot for FDB programming.
- The client does NOT notify any controllers about this change.
- The client does NOT perform a new FullUpload or FullDownload; it simply uses the already-maintained state snapshot from the new authoritative controller.
- The new authoritative controller MUST have `Synced = true` (only synchronized controllers are eligible for selection).

---

## 3. Client Authoritative Controller Selection (Stable Duration Model)
**Controller Synchronization Architecture**:
- Controllers do NOT synchronize with each other. Each controller independently maintains its own view of the network state.
- Clients connect to all configured controllers and upload their state (MACs, probe results) to all controllers.
- Each client independently selects ONE controller as **Authoritative** and ONLY applies configuration and FDB updates from that source. Updates from non-authoritative controllers are ignored.
- Because all clients use the same selection algorithm and receive the same controller status information, they will converge on the same authoritative controller.

**Selection Algorithm** (applied independently by each client):
- **Candidate Pool**: Only controllers where `Synced = true` are eligible for selection. Controllers with `Synced = false` are excluded.
1. **Primary Criterion: Highest `client_count`** (most clients connected)
2. **Tie-breaker 1: Oldest `last_client_change_timestamp`** (rewards stable controller-client connections; smaller timestamp = longer stability)
3. **Tie-breaker 2: Lowest `controller_id`** (public key comparison for deterministic tie-breaking)

**Controller State Update**:
- When the stream socket layer detects a client connection breakage (via timeout/socket closure), the controller updates its `last_client_change_timestamp` to the current Unix timestamp and decrements `client_count`.
- When a new client connects, the controller increments `client_count` and updates `last_client_change_timestamp`.

**MAC Address Conflicts**:
- Controllers do not coordinate MAC ownership. If a client announces a MAC that conflicts with another client's announcement, the controller compares the `learned_timestamp` values and keeps the entry with the **newest timestamp** (highest value).
- If timestamps are equal, the controller keeps the most recently received announcement (last-write-wins).
- Note: In a properly configured network, MAC addresses within the same bridge domain should be unique. Conflicts indicate misconfiguration or VM migration.

---

## 4. Client Startup & Validation
- **Initial Connection**: The client connects to all configured controllers.
- **Bidirectional Configuration Synchronization**: The client performs a two-way configuration exchange with all controllers:
  1. **Client-side configuration initialization**: The client initializes its local configuration to `null` (no configuration loaded yet).
  2. **FullUpload**: The client uploads its complete local state (MAC table) to all controllers. This upload includes the client's current configuration (which is `null` during initial startup).
  3. **FullDownload**: The client issues a `ControllerStateRequest` to all controllers and receives full `ControllerStateUpdate` responses containing configuration parameters (`vxlan`, `probing`, `routing` including `base_latency_ms`).
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
  ip link set {vxlan_name} master {bridge_name}
  ip link set {vxlan_name} type bridge_slave hairpin on
  ip link set {vxlan_name} up
  ```
  - The Linux kernel automatically handles the VXLAN UDP socket; no additional user-space UDP socket is required.
  - The `port` parameter specifies both the source and destination UDP port for VXLAN encapsulation.
  - `bind_addr` is the local IP address (from `address_families.v4.bind_addr` or `address_families.v6.bind_addr`) used as the VXLAN tunnel source.
  - **Hairpin Mode**: MUST be enabled on the VXLAN interface to allow packets received from one VXLAN tunnel to be forwarded back out through another VXLAN tunnel (required for multi-hop routing, e.g., A→B→C where B forwards traffic between two VXLAN tunnels).
- **Endpoint Terminology**:
  - **Control Endpoint**: `IP:communication_port` used for encrypted WireGuard control plane traffic (client-controller RPC, client-client probes).
  - **VXLAN Destination IP**: The same IP address from the control endpoint is used for VXLAN data plane traffic. When programming FDB entries, only the IP portion of the peer's endpoint is extracted (without port, since the VXLAN port is fixed by configuration).
  - The `ClientEndpoints` dataset from the controller contains the full `IP:port` for each client. When programming VXLAN FDB entries, clients use only the IP portion of these controller-provided endpoints.

### 5.1. Client Roaming & Endpoint Discovery
- **Endpoint Discovery**: The unified encryption layer learns a client's public endpoint from the source address of authenticated packets arriving on the established stream socket session.
- **Roaming Mode Selection**: Per §1.1 the layer supports `disabled`, `same_af`, and `all`. This project pins modes as follows:
  - **Client-Controller Link**: Uses `same_af` so controllers accept endpoint moves within the same address family (e.g., client NAT address change).
  - **Client-Client Link**: Uses `disabled`; clients only trust controller-advertised endpoints and use `SetPeerEndpoint` to update them.
- **Update Propagation**: When a controller detects an endpoint change (via the encryption layer's roaming event channel), it MUST update `last_client_change_timestamp` and broadcast a `ControllerStateUpdate` message containing the new endpoint in the `ClientEndpoints` dataset so all peers can synchronize their peer tables.
 
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
Each controller independently issues `ControllerProbeRequest` messages based on:
1. **Periodic (Scheduled)**: Calculate aligned UTC times using local clock: `next_cycle_start = ceil(utc_now / probe_interval_s) * probe_interval_s`. When the time arrives, issue a `ControllerProbeRequest` with:
   ```go
   probe_id = float64(next_cycle_start)  // e.g., 1727865600.0
   ```
2. **On-Demand (On New Client Join)**:
   - When a client transitions from offline to online (stream socket connection established), start a timer set to `sync_new_client_delay` seconds.
   - If another client connects during this delay, reset the timer.
   - When the timer expires (no new clients connected for `sync_new_client_delay` seconds), issue a `ControllerProbeRequest` with:
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

The controller does NOT track responses to its own `ControllerProbeRequest`. The issuance is fire-and-forget.

**Phase 2: ControllerProbeRequestAck Collection & Statistics** (Triggered by any ControllerProbeRequestAck)
When a controller receives a `ControllerProbeRequestAck` with a `probe_id`:
- If this is the first `ControllerProbeRequestAck` for this `probe_id`, start tracking this probing cycle.
- Begin collecting `ControllerProbeResult` messages for this `probe_id`.
- This mechanism works identically for all controllers, regardless of who issued the original `ControllerProbeRequest`.
- **Late Arrivals**: Any `ControllerProbeResult` that arrives after the calculation trigger (see §6.3 step 4) MUST be discarded and logged as late/ignored.

**Constraint**: `sync_new_client_delay` MUST satisfy: `sync_new_client_delay > probe_times * in_probe_interval_ms + probe_timeout_ms + probe_request_timeout` to ensure the on-demand probe cycle can complete before triggering another.

**Client-Side Probing Protocol**:
When a client receives a `ControllerProbeRequest`:
1. **Authoritative Check**: The client checks if the issuing controller is its current authoritative controller.
   - **If not authoritative**: Ignore the `ControllerProbeRequest` entirely. Do not send acknowledgment, do not execute probing.
   - **If authoritative**: Proceed to step 2.
2. **Broadcast Acknowledgment**: The client immediately sends a `ControllerProbeRequestAck` (via stream socket) to **all connected controllers**, containing the same `probe_id`. This allows all controllers (both authoritative and non-authoritative) to track probing progress.
3. **Execute Probing**: The client executes the probing cycle (see execution flow below).

**Probing Execution Flow (OWD Measurement)**:
When a client executes probing (only for requests from the authoritative controller):
- **Transport**: Probe packets (`ClientProbeRequest` and `ClientProbeResponse`) are transmitted through the encrypted WireGuard connection on `communication_port`. These control messages do not use the stream socket reliability layer (probe loss is handled by aggregation logic).
- **Multi-Path Probing**: The client MUST probe all available address families (v4 and v6) for each peer independently:
  - If both `encryptionLayerV4` and `encryptionLayerV6` exist, probe the peer through both encryption layer instances.
  - Each address family produces an independent set of OWD measurements.
  - The client maintains separate send time tracking for each `{peer_pubkey, address_family, sub_id}` tuple.
- **Execution**:
  1. For each peer, for each available address family (v4/v6), the client initiates a series of probe requests.
  2. A total of `probe_times` requests are sent per address family, spaced `in_probe_interval_ms` apart. Each request has a `sub_id` (from 0 to `probe_times - 1`).
  3. **Request**: Client A sends a `ClientProbeRequest` to Peer B containing `{probe_id, sub_id, address_family}`. Client A records its local send time for this triplet.
  4. **Response**: Peer B immediately replies with a `ClientProbeResponse` containing `{probe_id, sub_id, address_family, peer_local_time}` where `peer_local_time` is Peer B's current local time when processing the request.
  5. **OWD Calculation**: When Client A receives the response, it calculates the true one-way delay (OWD) from A to B via the specified address family: `OWD = peer_local_time - local_send_time`. This measures the actual one-way delay and can be negative if clocks are skewed, which is acceptable for Floyd-Warshall algorithm.

### 6.2. Local Aggregation & Upload
- **Result Collection**: After sending all probe requests in a cycle, the client waits for responses up to `probe_timeout_ms` for each request.
- **Per-Address-Family Aggregation**: Once the probing window for the cycle is over (all requests sent and timeout expired), the client aggregates the results separately for each peer and address family:
  - For each peer, for each address family (v4/v6), calculate the **median OWD** from all successful response messages for that address family.
  - If no responses were received for a specific address family, the OWD for that address family is marked as `INF_NUM` (999999).
  - The client records the success rate (`successful_probes / probe_times`) per address family for potential future use.
  - **Result Structure**: Each peer's result contains both `v4_latency_ms` and `v6_latency_ms` (see `PeerMetrics` in §2).
- **Upload**: The client then uploads a single `ProbeResult` message for the completed cycle (`probe_id`) to **all connected controllers** (via stream socket). This message contains the median OWD and success rate for every peer and address family combination.

### 6.3. Controller Processing & Path Selection

**Synchronization Barrier (All Controllers - Identical Logic)**:
Every controller performs identical collection and calculation logic, triggered by receiving `ControllerProbeRequestAck` messages:

1. **Cycle Initiation**: When a controller receives the **first** `ControllerProbeRequestAck` for a given `probe_id`, it initializes tracking for this probing cycle:
   - Create a tracking state for this `probe_id`
   - Start a timeout timer: `probe_times * in_probe_interval_ms + probe_timeout_ms + probe_request_timeout`
   - Initialize an empty set to track which clients have submitted results

2. **Ack Collection**: Track which online clients have sent `ControllerProbeRequestAck` for this `probe_id`. Since `ControllerProbeRequestAck` is broadcast to all controllers, every controller receives identical acknowledgments.

3. **Result Collection**: Wait for `ProbeResult` messages with matching `probe_id` from all acknowledged clients.

4. **Trigger Calculation**: The controller proceeds to routing calculation when:
   - All acknowledged clients have submitted their `ProbeResult`, OR
   - The timeout expires (whichever comes first)

5. **Broadcast Update**: After calculation, the controller broadcasts a `ControllerStateUpdate` to all connected clients.

**Key Design Points**:
- **ControllerProbeRequest issuance is decoupled**: Controllers issue `ControllerProbeRequest` independently. The issuance does NOT create any tracking state.
- **ControllerProbeRequestAck triggers collection**: The first `ControllerProbeRequestAck` for a `probe_id` initiates the collection phase. All controllers use identical logic.
- **Only authoritative `ControllerProbeRequest` is honored**: Clients ignore `ControllerProbeRequest` from non-authoritative controllers. Only the authoritative controller's request triggers client probing.
- **All controllers synchronize identically**: Since `ControllerProbeRequestAck` is broadcast to all controllers, all controllers observe the same set of responding clients and perform identical calculations.
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
- **Negative Cycle Detection**: Before accepting the routing calculation results, the controller MUST check for negative cycles in the graph (which indicate severe clock skew or NTP synchronization failure):
  - After running Floyd-Warshall, check if any `dist[i][i] < 0` (negative self-loop indicates negative cycle).
  - If a negative cycle is detected:
    1. Log a **critical error** with details about the affected nodes and edge weights.
    2. **Mitigation**: Set all negative-weight edges to 0 and rerun Floyd-Warshall to produce a usable routing table.
    3. Alert the operator to check NTP synchronization across all nodes.
    4. Continue operating with the sanitized routing table (degraded but functional).
- The output `RouteMatrix` is a next-hop lookup table:
  - **Data Structure**: `RouteMatrix[src_pubkey][dst_pubkey] = next_hop_client_and_address_family` (string, the public key of the next hop client)
  - **Unreachable paths**: If no path exists between src and dst, the entry is empty/null/omitted (implementation choice).
  - **Direct connection**: If src can reach dst directly (one hop), `RouteMatrix[src][dst] = dst`.
- The `RouteMatrix` does NOT include latency values or distance metrics. It is purely a forwarding table.
- The routing table is then broadcast in a `ControllerStateUpdate` message to all connected clients.

---

## 7. Client FDB Programming (Decoupled Model)

### 7.1 BridgeFDBController Implementation

**BridgeFDBController**: A dedicated component for monitoring and managing FDB entries on a Linux bridge with controlled VXLAN devices.

**Initialization**:
```go
type BridgeFDBController interface {
    // Get live FDB update events (RTM_NEWNEIGH/RTM_DELNEIGH)
    EventChannel() <-chan FDBEvent

    // Request full FDB dump with tracking ID
    RequestDump(dumpID string) error

    // Write FDB entry to specified slave device with destination IP
    WriteFDBEntry(mac net.HardwareAddr, slave string, dstIP net.IP) error

    // Remove FDB entry from specified slave device
    RemoveFDBEntry(mac net.HardwareAddr, slave string) error

    // Check if a MAC address is local (exists in local_mac_db)
    // Used by multicast forwarder for loop prevention
    IsLocalMAC(mac net.HardwareAddr) bool

    Close() error
}

type FDBEvent struct {
    Type     FDBEventType
    MAC      net.HardwareAddr
    Slave    string      // Interface name (e.g., "vxlan-v4", "eth0")
    DstIP    net.IP      // Destination IP for VXLAN entries
    DumpID   string      // Set only for RTM_GETNEIGH dump responses
}

type FDBEventType int
const (
    FDBEventAdd    FDBEventType = iota  // RTM_NEWNEIGH
    FDBEventRemove                      // RTM_DELNEIGH  
    FDBEventDump                        // RTM_GETNEIGH response
)

func NewBridgeFDBController(bridgeName string, ignoredSlaves []string, debounceMs int) (BridgeFDBController, error)
```

**Key Features**:

1. **Single Netlink Socket**: Uses one netlink socket internally to ensure no gap between dump and subsequent updates, maintaining consistency.

2. **Bridge Scope**: Only monitors FDB changes on the specified `bridge_name` and its slave ports.

3. **Ignored Slaves Filtering**: Filters out FDB entries on `ignoredSlaves` (specifically the controller-managed VXLAN devices "vxlan-v4" and "vxlan-v6") to avoid processing remote MAC entries. These controller-managed VXLAN devices contain static FDB entries for remote nodes programmed by the controller (§7.2), which should not be reported as locally owned MACs. All other bridge slave ports—including physical interfaces (eth0), virtual interfaces (tap0, veth), and user-created VXLAN devices—are monitored for locally owned MAC addresses that need to be announced to controllers.

4. **Debounced Updates**: Combines multiple FDB changes within `debounceMs` interval into a single batched update to prevent excessive event generation. This mechanism also mitigates race conditions during FDB programming operations by allowing transient intermediate states to settle before triggering application-level processing.

5. **Gap-Free Monitoring**: The single socket design ensures all FDB changes are captured without missing events between dump and live monitoring.

6. **Tracked Dumps**: `RequestDump()` with a tracking ID allows the application to correlate dump responses with specific requests via the `DumpID` field in `FDBEvent`.

**Race Condition Mitigation**:
The debounce mechanism handles rapid FDB state transitions gracefully. For example, when moving a MAC from vxlan-v6 to vxlan-v4 (see §7.2 implementation), the sequence `NeighSet(v4) → NeighDel(v6)` may briefly trigger intermediate FDB events. The debounce window ensures these transient states are collapsed into a single final event reflecting the actual end state, preventing unnecessary MAC synchronization messages to controllers.

**MAC Ownership Abstraction**:
The BridgeFDBController abstracts away slave interface details when reporting MAC changes to the application layer. When monitoring local MAC addresses learned on physical/virtual bridge slaves (eth0, tap0, veth, etc.), the controller only cares about the MAC address itself—not which specific local slave interface it was learned from. This design means that a MAC moving between local slaves (e.g., `FDBEventRemove(mac, eth0)` followed by `FDBEventAdd(mac, tap0)`) within the debounce window will cancel out, resulting in no `LocalMACAnnounce` message being sent to controllers (the MAC is still owned by this client node, just moved between local interfaces). From the controller's perspective, all that matters is whether the MAC exists on this client node or not.

**Usage Pattern**:
```go
// Initialize with bridge name and ignored VXLAN devices
fdbController := NewBridgeFDBController("br-vxlan", []string{"vxlan-v4", "vxlan-v6"}, 500)

// Monitor live FDB changes
go func() {
    for event := range fdbController.EventChannel() {
        switch event.Type {
        case FDBEventAdd, FDBEventRemove:
            // Process live FDB updates
            syncMACToControllers(event)
        case FDBEventDump:
            // Process full dump response
            handleDumpResponse(event.DumpID, event)
        }
    }
}()

// Write controller-managed FDB entries
fdbController.WriteFDBEntry(macAddr, "vxlan-v4", peerIP)
```

**Integration with MAC Learning**:
- **Local MAC Discovery**: Use `RequestDump()` during initialization to build `local_mac_db`. MAC addresses learned on all bridge slave ports are included, except those on controller-managed VXLAN devices (vxlan-v4, vxlan-v6) which represent remote MACs.
- **Runtime Monitoring**: Process `FDBEventAdd`/`FDBEventRemove` events to maintain synchronized MAC state. The `ignoredSlaves` filter (containing only vxlan-v4 and vxlan-v6) ensures only locally owned MACs trigger updates.
- **Controller Updates**: Send `LocalMACAnnounce` messages when locally owned MAC addresses appear or disappear on the bridge (regardless of which non-ignored slave interface they're attached to).
- **Loop Prevention Support**: The `IsLocalMAC(mac)` API checks if a MAC address exists in `local_mac_db`. This is used by the multicast forwarder to distinguish locally-originated packets (which should be forwarded to the controller) from remote packets (which should be ignored to prevent loops). Implementation should be thread-safe with read lock on `local_mac_db`.

### 7.2 FDB Programming from Authoritative Controller

**Data from Authoritative Controller**: The client only acts upon the `MacOwnership` and `RouteMatrix` datasets from its chosen authoritative controller. Updates from non-authoritative controllers are ignored.

**Client-Side FDB Resolution**: The client programs two types of FDB entries:

#### 1. Multicast/Broadcast Forwarding via Controller (No Default Routes)
**Design Decision**: To avoid broadcast packet duplication and loops in mixed address family topologies, this project does **NOT** install `00:00:00:00:00:00` default routes. Instead, multicast and broadcast packets are forwarded through a centralized controller-based relay.

**Rationale**:
- **Hairpin + Default Routes = Duplication**: With hairpin mode and default routes to all peers, broadcast packets would be duplicated exponentially as network size grows. For example, with nodes A, B (dual-stack) and C (v4-only), a broadcast from C would reach B twice (directly via v4, and via A's v6 hairpin).
- **Centralized Control Eliminates Loops**: By routing all multicast/broadcast through the authoritative controller, each packet is delivered exactly once to each peer, regardless of address family configurations.
- **Unicast Unaffected**: Specific MAC entries (§7.2.2) handle all unicast traffic normally via VXLAN direct forwarding.

**Multicast Forwarder Service**:
Each client runs a `multicast_forwarder` service that:
1. **Captures Multicast/Broadcast Packets**:
   - Uses **libpcap** to monitor the bridge interface for packets with multicast/broadcast destination MAC addresses.
   - Filter: Capture only packets where the least significant bit of the first octet of the destination MAC is 1 (multicast/broadcast bit).
   - Exclude: Do not capture packets originating from VXLAN devices (to avoid loops).
   - Capture complete Ethernet frames (L2 header + payload).

2. **Forwards to Authoritative Controller**:
   - Encapsulates captured frames in `MulticastPacket` messages.
   - Sends to the client's currently selected authoritative controller via the stream socket.
   - Includes source client ID and capture timestamp.

3. **Controller Relay**:
   - The authoritative controller receives `MulticastPacket` from the source client.
   - Broadcasts `MulticastForward` messages to **all other connected clients** (excluding the source client).
   - The `MulticastForward` message contains the original Ethernet frame.

4. **Injection into Local Bridge**:
   - **All clients** (regardless of authoritative controller selection) process `MulticastForward` messages.
   - Use a **raw socket** (AF_PACKET) to inject the received Ethernet frame into the local bridge interface.
   - The injected packet appears as if it arrived from a local source, allowing normal bridge forwarding to local ports.

**Implementation Notes**:
- **libpcap Filter**: `ether multicast or ether broadcast`
- **Raw Socket**: Create `socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))` and bind to bridge interface.
- **Frame Injection**: Write complete Ethernet frame (dst MAC, src MAC, ethertype, payload) to raw socket.
- **Loop Prevention**: The multicast forwarder must not forward packets injected by remote peers (via `MulticastForward`). Since libpcap cannot determine the incoming slave interface, use source MAC filtering:
  - Check if the packet's source MAC exists in the local MAC database (maintained by `BridgeFDBController`).
  - If source MAC is local (exists in `local_mac_db`), this packet originated from a local VM → forward to controller.
  - If source MAC is not local (injected via `MulticastForward` or arrived from VXLAN), ignore it to prevent loops.
  - Add `IsLocalMAC(mac)` API to `BridgeFDBController` for this check.
- **Rate Limiting**: Consider rate limiting multicast forwarding to prevent abuse (e.g., max 1000 pps per client).

**Message Flow Example**:
```
Client C sends ARP broadcast on local bridge
↓
multicast_forwarder captures Ethernet frame via libpcap
↓
C sends MulticastPacket to authoritative controller
↓
Controller receives MulticastPacket from C
↓
Controller broadcasts MulticastForward to clients A, B, D (excluding C)
↓
A, B, D receive MulticastForward
↓
A, B, D inject Ethernet frame into their local bridges via raw socket
↓
Local devices on A, B, D receive the ARP broadcast
```

**Advantages**:
- **Zero Duplication**: Each packet delivered exactly once to each peer.
- **Topology Independent**: Works regardless of address family configurations.
- **Scalable**: O(n) forwarding complexity at controller (better than O(n²) with default routes + hairpin).

**Disadvantages**:
- **Latency**: Multicast/broadcast packets have additional hop through controller.
- **Controller Bandwidth**: Controller must relay all multicast/broadcast traffic.
- **Single Point of Failure**: If authoritative controller is down, multicast forwarding stops (but unicast continues working).

**ARP/ND Proxy Integration**:

To further reduce broadcast traffic, the system can implement ARP/ND proxy (similar to EVPN's ARP suppression):

**Mechanism**:
1. **MAC-IP Binding Learning from MulticastForward**:
   - **Design Decision**: No separate ARP/ND synchronization protocol needed. ARP/ND information is already contained in `MulticastForward` messages.
   - When a client receives a `MulticastForward` message (containing a multicast/broadcast frame from a remote peer):
     1. **Parse the Ethernet frame** to extract protocol information.
     2. **If ARP packet**: Extract sender's IP (SourceProtAddress) and MAC (SourceHwAddress).
     3. **If IPv6 Neighbor Solicitation/Advertisement**: Extract source IPv6 and link-layer address.
     4. **Update local neighbor table**: Store `IP → MAC` binding with timestamp.
     5. **Optional VLAN filtering**: If the bridge is VLAN-aware, only learn bindings from the appropriate VLAN.
   - This approach naturally distributes ARP/ND knowledge across all clients without additional messages.

2. **Local Neighbor Table Management**:
   - Each client maintains a local neighbor table: `map[IP]NeighborEntry`.
   - Entry structure:
     ```go
     type NeighborEntry struct {
         MAC       net.HardwareAddr
         Timestamp int64  // Unix timestamp when learned/refreshed
     }
     ```
   - Entries expire after `neighbor_timeout` seconds (configured in client config).
   - Expired entries are removed from the table (lazy deletion or periodic cleanup).

3. **Userspace ARP Proxy (Recommended Approach)**:
   - **Design Decision**: Use pure userspace ARP proxy instead of kernel mechanisms.
   - **Rationale**:
     - Kernel neighbor cache (`ip neigh add`) on bridge interface does not trigger ARP proxy for L2 bridged traffic.
     - VXLAN proxy mode (`ip link set vxlan-v4 type vxlan proxy on`) is designed for L3 VXLAN gateway scenarios, not pure L2 overlay.
     - Userspace proxy provides full control, flexibility, and consistency with the controller-synchronized ARP table.

4. **ARP Request Handling (Userspace)**:
   - When multicast forwarder captures an ARP request via libpcap:
     1. Extract target IP from ARP request.
     2. Check if target IP exists in local `neighborTable` (learned from `MulticastForward` messages).
     3. Check if entry is still valid (not expired based on `neighbor_timeout`).
     4. **If found and valid**: Generate ARP reply locally and inject via raw socket (do NOT forward to controller).
     5. **If not found or expired**: Forward original ARP request to controller as `MulticastPacket` (existing multicast forwarding path).
   - This provides local ARP resolution for known IPs while allowing discovery for unknown IPs.

5. **IPv6 Neighbor Discovery**:
   - Similar logic for IPv6 Neighbor Solicitation messages.
   - Check `neighborTable` for IPv6 addresses.
   - Generate Neighbor Advertisement if found and valid, otherwise forward NS to controller.

6. **Learning from Injected Packets**:
   - When injecting a `MulticastForward` frame via raw socket:
     - Parse the frame before injection.
     - Extract IP→MAC bindings from ARP/ND packets.
     - Update local `neighborTable` with the learned binding.
     - Set timestamp to current time.
   - This ensures the local neighbor table is populated before the frame is injected.

**Benefits**:
- Reduces ARP/ND broadcast traffic by 90%+
- Faster ARP resolution (local response)
- Works seamlessly with raw socket injection (proxy-generated packets are also injected via raw socket)

**Userspace ARP Proxy Flow**:
```
1. Local VM sends ARP request "Who has 10.0.0.2?"
   ↓
2. ARP request arrives on bridge (broadcast)
   ↓
3. libpcap captures the packet (multicast forwarder)
   ↓
4. Check arpCache[10.0.0.2]
   ↓
   ┌─────────────┬─────────────┐
   │ Found       │ Not Found   │
   ↓             ↓
5a. Generate    5b. Forward to
    ARP reply       controller as
    ↓               MulticastPacket
6a. Inject via      ↓
    raw socket  6b. Controller
    ↓               broadcasts to
7a. Bridge          all clients
    forwards        ↓
    to VM       7b. Target VM
    ↓               receives and
8a. Done            replies
    (local)         ↓
                8b. Reply forwarded
                    back via controller
```

**Key Point**: This is **pure userspace proxy** - kernel ARP mechanisms are NOT used because:
- `ip neigh add` on bridge: Does not trigger proxy for L2 bridging (only works for L3 routing)
- `vxlan proxy on`: Designed for L3 VXLAN gateway mode, not L2 overlay
- Userspace approach: Full control, consistent with controller-synchronized state

**Important Note on Learning**:
- **ARP Reply/ND Advertisement packets are unicast** (destination MAC is the requester's MAC, not broadcast/multicast).
- These unicast packets will **NOT** be captured by the `ether multicast or ether broadcast` BPF filter.
- Instead, learn IP→MAC bindings from **ARP Request** packets (which are broadcast):
  - ARP Request contains sender's IP (SourceProtAddress) and MAC (SourceHwAddress)
  - Extract this binding and sync to controller
- For IPv6, learn from **Neighbor Solicitation** packets (which are multicast to solicited-node address)
- **Alternative**: Use promiscuous mode capture on a separate pcap handle to also capture unicast ARP/ND replies for more complete learning, but this is optional as learning from requests is usually sufficient.

**Multicast Forwarder Implementation Example**:
```go
// Client-side multicast forwarder service
type MulticastForwarder struct {
    bridgeName          string
    pcapHandle          *pcap.Handle
    rawSocket           int
    authControllerConn  StreamSocket
    selfPubKey          string
    fdbController       BridgeFDBController  // For loop prevention via IsLocalMAC()
    neighborTimeout     int                  // Neighbor entry timeout in seconds

    // Neighbor table learned from MulticastForward messages
    neighborTable       map[string]NeighborEntry  // IP -> (MAC, timestamp)
    neighborMutex       sync.RWMutex
}

type NeighborEntry struct {
    MAC       net.HardwareAddr
    Timestamp int64  // Unix timestamp when learned/refreshed
}

func (mf *MulticastForwarder) Start() error {
    // Open pcap handle on bridge interface
    handle, err := pcap.OpenLive(mf.bridgeName, 65535, true, pcap.BlockForever)
    if err != nil {
        return err
    }
    mf.pcapHandle = handle

    // Set BPF filter: capture multicast/broadcast, exclude VXLAN devices
    filter := "ether multicast or ether broadcast"
    err = handle.SetBPFFilter(filter)
    if err != nil {
        return err
    }

    // Create raw socket for injection
    rawSock, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(syscall.ETH_P_ALL)))
    if err != nil {
        return err
    }
    mf.rawSocket = rawSock

    // Bind raw socket to bridge interface
    ifIndex := getInterfaceIndex(mf.bridgeName)
    addr := syscall.SockaddrLinklayer{
        Protocol: htons(syscall.ETH_P_ALL),
        Ifindex:  ifIndex,
    }
    err = syscall.Bind(rawSock, &addr)
    if err != nil {
        return err
    }

    // Start capture loop
    go mf.captureLoop()
    return nil
}

func (mf *MulticastForwarder) captureLoop() {
    packetSource := gopacket.NewPacketSource(mf.pcapHandle, mf.pcapHandle.LinkType())

    for packet := range packetSource.Packets() {
        ethLayer := packet.Layer(layers.LayerTypeEthernet)
        if ethLayer == nil {
            continue
        }

        eth := ethLayer.(*layers.Ethernet)

        // Check if destination is multicast/broadcast
        if !(eth.DstMAC[0]&1 == 1) {
            continue
        }

        // Loop prevention: Only forward packets from local MACs
        // Packets with non-local source MAC are either:
        // 1. Injected by MulticastForward from remote peers
        // 2. Arrived via VXLAN from remote nodes
        // Both should NOT be forwarded again to prevent loops
        if !mf.fdbController.IsLocalMAC(eth.SrcMAC) {
            continue  // Ignore non-local source, prevent loop
        }

        // Try ARP proxy first (using neighbor table learned from MulticastForward)
        if mf.tryARPProxy(packet) {
            continue  // Successfully handled locally, don't forward to controller
        }

        // Forward to authoritative controller
        msg := &MulticastPacket{
            SourceClientId:   mf.selfPubKey,
            EthernetFrame:    packet.Data(),
            CaptureTimestamp: time.Now().Unix(),
        }

        mf.authControllerConn.Write(encodeMessage(msg))
    }
}

func (mf *MulticastForwarder) tryARPProxy(packet gopacket.Packet) bool {
    arpLayer := packet.Layer(layers.LayerTypeARP)
    if arpLayer == nil {
        return false  // Not an ARP packet
    }

    arp := arpLayer.(*layers.ARP)

    // Only handle ARP requests
    if arp.Operation != layers.ARPRequest {
        return false
    }

    targetIP := net.IP(arp.DstProtAddress).String()

    // Check if we have this IP in our neighbor table
    mf.neighborMutex.RLock()
    entry, exists := mf.neighborTable[targetIP]
    mf.neighborMutex.RUnlock()

    if !exists {
        return false  // Don't have this entry, forward to controller
    }

    // Check if entry has expired
    if time.Now().Unix()-entry.Timestamp > int64(mf.neighborTimeout) {
        // Entry expired, remove it and forward to controller
        mf.neighborMutex.Lock()
        delete(mf.neighborTable, targetIP)
        mf.neighborMutex.Unlock()
        return false
    }

    // Generate ARP reply using the learned MAC
    reply := mf.generateARPReply(arp, entry.MAC)

    // Inject reply via raw socket (this will NOT learn again, as it's our own injection)
    syscall.Write(mf.rawSocket, reply)

    return true  // Successfully proxied
}

func (mf *MulticastForwarder) generateARPReply(request *layers.ARP, targetMAC net.HardwareAddr) []byte {
    // Build Ethernet header
    eth := layers.Ethernet{
        SrcMAC:       targetMAC,
        DstMAC:       request.SourceHwAddress,
        EthernetType: layers.EthernetTypeARP,
    }

    // Build ARP reply
    arp := layers.ARP{
        AddrType:          layers.LinkTypeEthernet,
        Protocol:          layers.EthernetTypeIPv4,
        HwAddressSize:     6,
        ProtAddressSize:   4,
        Operation:         layers.ARPReply,
        SourceHwAddress:   targetMAC,
        SourceProtAddress: request.DstProtAddress,
        DstHwAddress:      request.SourceHwAddress,
        DstProtAddress:    request.SourceProtAddress,
    }

    buf := gopacket.NewSerializeBuffer()
    opts := gopacket.SerializeOptions{}
    gopacket.SerializeLayers(buf, opts, &eth, &arp)

    return buf.Bytes()
}

func (mf *MulticastForwarder) InjectPacket(frame []byte) error {
    // Parse frame and learn IP→MAC bindings before injection
    mf.learnFromFrame(frame)

    // Inject received frame into local bridge
    _, err := syscall.Write(mf.rawSocket, frame)
    return err
}

func (mf *MulticastForwarder) learnFromFrame(frame []byte) {
    packet := gopacket.NewPacket(frame, layers.LayerTypeEthernet, gopacket.Default)

    // Learn from ARP packets
    if arpLayer := packet.Layer(layers.LayerTypeARP); arpLayer != nil {
        arp := arpLayer.(*layers.ARP)

        // Learn sender's IP→MAC binding
        senderIP := net.IP(arp.SourceProtAddress).String()
        senderMAC := net.HardwareAddr(arp.SourceHwAddress)

        mf.neighborMutex.Lock()
        mf.neighborTable[senderIP] = NeighborEntry{
            MAC:       senderMAC,
            Timestamp: time.Now().Unix(),
        }
        mf.neighborMutex.Unlock()
    }

    // Learn from IPv6 Neighbor Solicitation
    if icmpv6Layer := packet.Layer(layers.LayerTypeICMPv6NeighborSolicitation); icmpv6Layer != nil {
        ipv6Layer := packet.Layer(layers.LayerTypeIPv6)
        ethLayer := packet.Layer(layers.LayerTypeEthernet)

        if ipv6Layer != nil && ethLayer != nil {
            ipv6 := ipv6Layer.(*layers.IPv6)
            eth := ethLayer.(*layers.Ethernet)

            sourceIP := ipv6.SrcIP.String()
            sourceMAC := eth.SrcMAC

            mf.neighborMutex.Lock()
            mf.neighborTable[sourceIP] = NeighborEntry{
                MAC:       sourceMAC,
                Timestamp: time.Now().Unix(),
            }
            mf.neighborMutex.Unlock()
        }
    }

    // Learn from IPv6 Neighbor Advertisement
    if icmpv6Layer := packet.Layer(layers.LayerTypeICMPv6NeighborAdvertisement); icmpv6Layer != nil {
        ipv6Layer := packet.Layer(layers.LayerTypeIPv6)
        ethLayer := packet.Layer(layers.LayerTypeEthernet)

        if ipv6Layer != nil && ethLayer != nil {
            ipv6 := ipv6Layer.(*layers.IPv6)
            eth := ethLayer.(*layers.Ethernet)

            sourceIP := ipv6.SrcIP.String()
            sourceMAC := eth.SrcMAC

            mf.neighborMutex.Lock()
            mf.neighborTable[sourceIP] = NeighborEntry{
                MAC:       sourceMAC,
                Timestamp: time.Now().Unix(),
            }
            mf.neighborMutex.Unlock()
        }
    }
}

// Controller-side relay
func (ctrl *Controller) handleMulticastPacket(sourceClient string, msg *MulticastPacket) {
    // Broadcast to all other clients
    for clientPubKey, clientConn := range ctrl.connectedClients {
        if clientPubKey == sourceClient {
            continue  // Skip source
        }

        forwardMsg := &MulticastForward{
            SourceClientId:       msg.SourceClientId,
            EthernetFrame:        msg.EthernetFrame,
            ControllerTimestamp:  time.Now().Unix(),
        }

        clientConn.Write(encodeMessage(forwardMsg))
    }
}
```

#### 2. Specific MAC Entries
For each MAC address in `MacOwnership`, determine which client owns it (e.g., MAC X → Client B with public key `pubkey_B`).
- Look up the path decision in `RouteMatrix[self_pubkey][pubkey_B]`, which returns a `PathSpec` containing `address_family` and `next_hop_client_pubkey`.
- **If the route is unreachable** (`RouteMatrix[self_pubkey][pubkey_B].address_family == ""`), do NOT program an FDB entry for this MAC. Traffic to this MAC will be dropped or handled by the bridge's default behavior.
- **If reachable** (`address_family == "v4"` or `"v6"`):
  - Determine the next-hop peer's destination IP from the controller-provided `ClientEndpoints[next_hop_client_pubkey]`:
    - If `address_family == "v4"`: use IP from `ClientEndpoints[next_hop_client_pubkey].v4_ip`
    - If `address_family == "v6"`: use IP from `ClientEndpoints[next_hop_client_pubkey].v6_ip`
  - Determine which VXLAN device to use based on `address_family`:
    - `"v4"` → vxlan-v4 device
    - `"v6"` → vxlan-v6 device
  - Program the bridge FDB entry using netlink

**Note**: The specific MAC entry points to the next-hop peer's endpoint IP (not necessarily the MAC owner's IP). For multi-hop paths (e.g., A→B→C), the FDB entry on A for C's MAC will use B's endpoint IP from `ClientEndpoints[B]`, not C's endpoint IP.

**Specific MAC Entries - FDB Programming Implementation**:
```go
// Install specific MAC entries only (no default routes)
// Note: Linux VXLAN requires TWO FDB entries per remote MAC:
// 1. Bridge FDB (master): For L2 forwarding decision
// 2. VXLAN FDB (self): For VXLAN encapsulation destination
func applyFDBEntry(mac string, ownerPubKey string) error {
    pathSpec := routeMatrix[selfPubKey][ownerPubKey]

    // Use next_hop_client_pubkey to determine the actual destination IP
    nextHopPubKey := pathSpec.NextHopClientPubkey
    // Get controller-provided endpoint information
    clientInfo := clientEndpoints[nextHopPubKey]

    hwAddr, _ := net.ParseMAC(mac)

    switch pathSpec.AddressFamily {
    case "v4":
        if clientInfo.V4IP == "" {
            log.Warn("v4 path selected but no v4_ip available in ClientEndpoints")
            return nil
        }
        targetLink, _ := netlink.LinkByName("vxlan-v4")
        targetIP := net.ParseIP(clientInfo.V4IP)  // Controller-provided endpoint IP

        // Step 1: Add VXLAN FDB entry (self) - for VXLAN encapsulation
        err := netlink.NeighSet(&netlink.Neigh{
            LinkIndex:    targetLink.Attrs().Index,
            State:        netlink.NUD_PERMANENT,
            Family:       unix.AF_BRIDGE,
            Flags:        netlink.NTF_SELF,  // VXLAN device's own FDB
            HardwareAddr: hwAddr,
            IP:           targetIP,          // VTEP destination
        })
        if err != nil {
            return err
        }

        // Step 2: Add Bridge FDB entry (master) - for L2 forwarding
        bridgeLink, _ := netlink.LinkByName(bridgeName)
        err = netlink.NeighSet(&netlink.Neigh{
            LinkIndex:    targetLink.Attrs().Index,  // vxlan-v4 interface
            State:        netlink.NUD_PERMANENT,
            Family:       unix.AF_BRIDGE,
            Flags:        netlink.NTF_MASTER,        // Bridge's FDB
            HardwareAddr: hwAddr,
            MasterIndex:  bridgeLink.Attrs().Index,  // br-vxlan
        })
        if err != nil {
            return err
        }

        // Step 3: Remove from v6 devices (both self and master)
        v6Link, _ := netlink.LinkByName("vxlan-v6")
        netlink.NeighDel(&netlink.Neigh{
            LinkIndex:    v6Link.Attrs().Index,
            HardwareAddr: hwAddr,
            Flags:        netlink.NTF_SELF,
        })
        netlink.NeighDel(&netlink.Neigh{
            LinkIndex:    v6Link.Attrs().Index,
            HardwareAddr: hwAddr,
            Flags:        netlink.NTF_MASTER,
        })

        return nil

    case "v6":
        if clientInfo.V6IP == "" {
            log.Warn("v6 path selected but no v6_ip available in ClientEndpoints")
            return nil
        }
        targetLink, _ := netlink.LinkByName("vxlan-v6")
        targetIP := net.ParseIP(clientInfo.V6IP)  // Controller-provided endpoint IP

        // Step 1: Add VXLAN FDB entry (self)
        err := netlink.NeighSet(&netlink.Neigh{
            LinkIndex:    targetLink.Attrs().Index,
            State:        netlink.NUD_PERMANENT,
            Family:       unix.AF_BRIDGE,
            Flags:        netlink.NTF_SELF,
            HardwareAddr: hwAddr,
            IP:           targetIP,
        })
        if err != nil {
            return err
        }

        // Step 2: Add Bridge FDB entry (master)
        bridgeLink, _ := netlink.LinkByName(bridgeName)
        err = netlink.NeighSet(&netlink.Neigh{
            LinkIndex:    targetLink.Attrs().Index,
            State:        netlink.NUD_PERMANENT,
            Family:       unix.AF_BRIDGE,
            Flags:        netlink.NTF_MASTER,
            HardwareAddr: hwAddr,
            MasterIndex:  bridgeLink.Attrs().Index,
        })
        if err != nil {
            return err
        }

        // Step 3: Remove from v4 devices (both self and master)
        v4Link, _ := netlink.LinkByName("vxlan-v4")
        netlink.NeighDel(&netlink.Neigh{
            LinkIndex:    v4Link.Attrs().Index,
            HardwareAddr: hwAddr,
            Flags:        netlink.NTF_SELF,
        })
        netlink.NeighDel(&netlink.Neigh{
            LinkIndex:    v4Link.Attrs().Index,
            HardwareAddr: hwAddr,
            Flags:        netlink.NTF_MASTER,
        })

        return nil

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
- `mss`: Maximum Segment Size for stream socket connections (in bytes). Set to `0` to enable automatic MSS probing. Recommended values: 1200-1400 bytes, or 0 for auto-detection (default: 0).
- `clients_allowlist`: An array of client public keys.
- `client_offline_timeout`: Duration in seconds to wait for a disconnected client to reconnect before removing its MAC entries and recomputing routes (default: 300).
- `sync_new_client_delay`: Duration in seconds to wait after a new client connects before triggering a `ControllerProbeRequest`. The timer resets if another client connects during this period (default: 5). Must satisfy: `sync_new_client_delay > probe_times * in_probe_interval_ms + probe_timeout_ms + probe_request_timeout`.
- `probe_request_timeout`: Duration in milliseconds to wait for `ProbeResult` after the probing window closes (default: 1000). Total wait time for all results is: `probe_times * in_probe_interval_ms + probe_timeout_ms + probe_request_timeout`.
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
- `mss`: Maximum Segment Size for stream socket connections (in bytes). Set to `0` to enable automatic MSS probing. Recommended values: 1200-1400 bytes, or 0 for auto-detection (default: 0).
- `clamp_mss_to_mtu`: `true` or `false`.
- `init_timeout`: Duration in seconds to wait during initialization mode before selecting the authoritative controller and programming FDB entries (default: 10). This allows all controllers to stabilize their `client_count` and `last_client_change_timestamp` before the client commits to an authoritative selection.
- `fdb_debounce_ms`: Debounce time in milliseconds for FDB change events (default: 500). FDB changes within this window are batched together before triggering MAC synchronization to controllers.
- `neighbor_timeout`: Duration in seconds for neighbor table entries to expire (default: 300). Neighbor entries learned from `MulticastForward` messages are automatically removed after this timeout. When an ARP/ND request arrives for an expired entry, it is forwarded to the controller for fresh resolution.
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
