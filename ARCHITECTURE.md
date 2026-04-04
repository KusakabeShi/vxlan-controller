# ARCHITECTURE.md — VXLAN Controller (Go)

本文件基於 DESIGN.md，整理出 Go 語言實作的架構細節，包含模組劃分、核心結構體、goroutine 設計、IPC/通訊流程。

---

## 目錄結構

```
vxlan-controller/
├── cmd/
│   ├── controller/main.go      # Controller 入口
│   └── client/main.go          # Client 入口
├── proto/
│   ├── messages.proto          # Protobuf 定義
│   └── messages.pb.go          # 產生的 Go 代碼
├── pkg/
│   ├── config/                 # YAML 配置解析
│   │   ├── client.go
│   │   ├── controller.go
│   │   ├── common.go
│   │   └── load.go
│   ├── crypto/                 # Noise IK handshake, ChaCha20-Poly1305, X25519
│   │   ├── noise.go
│   │   └── nonce.go
│   │   ├── session.go
│   │   ├── window.go
│   │   └── noise_test.go
│   ├── protocol/               # TCP framing, UDP packet, msg_type 定義
│   │   ├── framing.go
│   │   ├── msgtype.go
│   │   └── udp.go
│   ├── controller/             # Controller 核心邏輯
│   │   ├── controller.go
│   │   ├── routing.go          # Floyd-Warshall, AdditionalCost 加權, RouteMatrix
│   │   └── state.go
│   ├── client/                 # Client 核心邏輯
│   │   ├── authority.go        # 權威 Controller 選擇
│   │   ├── client.go
│   │   ├── comm_tcp.go         # TCP 連線/重連 + 收包迴圈
│   │   ├── comm_udp.go         # UDP communication channel (broadcast relay)
│   │   ├── controller_conn.go
│   │   ├── controller_state.go
│   │   ├── local_state.go      # 本地路由狀態 (debounced)
│   │   ├── send.go             # 封包上報（RouteUpdateBatch 等）
│   │   ├── probe.go            # Probe 執行 + probe channel handshake
│   │   ├── tap.go              # TAP device
│   │   ├── tap_loops.go        # tap read/write loops（含 rate limit）
│   │   ├── neigh_watch.go      # 鄰居表監聽 + debounce
│   │   ├── fdb.go              # FDB reconcile / netlink 寫入
│   │   ├── devices.go          # bridge/vxlan/tap 建立
│   │   ├── af_runtime.go       # per-AF UDP sockets (comm/probe)
│   │   └── api.go              # Unix socket REST API
│   ├── ntp/                    # NTP 校時
│   │   └── ntp.go
│   └── types/                  # 共用型別
│       └── types.go
├── go.mod
├── go.sum
├── DESIGN.md
├── tests/
│   └── test_all.sh
└── ARCHITECTURE.md
```

---

## 1. 共用型別

### 1.1 基礎 ID (`pkg/types`)

```go
// ClientID / ControllerID 是 X25519 public key（32 bytes）
type ClientID [32]byte
type ControllerID [32]byte

// AFName 代表一個 address family，例如 "v4", "v6", "asia_v4"
type AFName string
```

### 1.2 Controller 狀態型別 (`pkg/controller/state.go`)

```go
type Endpoint struct {
    IP                netip.Addr
    ProbePort         uint16
    CommunicationPort uint16
    VxlanDstPort      uint16
    Priority          int32
}

type ClientInfo struct {
    ClientID       types.ClientID
    Endpoints      map[types.AFName]*Endpoint
    LastSeen       time.Time
    AdditionalCost float64
}

type SelectedLatency struct {
    LatencyMs float64
    AF        types.AFName
}

type RouteEntry struct {
    NextHop types.ClientID
    AF      types.AFName
}

type RouteTableEntry struct {
    MAC    [6]byte
    IP     netip.Addr
    Owners map[types.ClientID]time.Time
}

type ControllerState struct {
    Clients          map[types.ClientID]*ClientInfo
    LatencyMatrix    map[types.ClientID]map[types.ClientID]*SelectedLatency
    RouteMatrix      map[types.ClientID]map[types.ClientID]*RouteEntry
    RouteTable       map[string]*RouteTableEntry
    LastClientChange time.Time
}
```

---

## 2. Controller 架構

### 2.0 Controller 配置

```go
type ControllerConfig struct {
    PrivateKey Key32B64 `yaml:"private_key"`

    AFSettings map[types.AFName]*ControllerAFConfig `yaml:"address_families"`

    ClientOfflineTimeout      Duration `yaml:"client_offline_timeout"`
    SyncNewClientDebounce     Duration `yaml:"sync_new_client_debounce"`
    SyncNewClientDebounceMax  Duration `yaml:"sync_new_client_debounce_max"`
    TopologyUpdateDebounce    Duration `yaml:"topology_update_debounce"`
    TopologyUpdateDebounceMax Duration `yaml:"topology_update_debounce_max"`

    Probing        ProbingConfig    `yaml:"probing"`
    AllowedClients []PerClientConfig `yaml:"allowed_clients"`
}

type ControllerAFConfig struct {
    Name              types.AFName `yaml:"name"`
    Enable            bool         `yaml:"enable"`
    BindAddr          Addr         `yaml:"bind_addr"`
    CommunicationPort uint16       `yaml:"communication_port"` // 同一 port 同時 listen TCP + UDP

    VxlanVNI          uint32 `yaml:"vxlan_vni"`
    VxlanDstPort      uint16 `yaml:"vxlan_dstport"`
    VxlanSrcPortStart uint16 `yaml:"vxlan_srcport_start"`
    VxlanSrcPortEnd   uint16 `yaml:"vxlan_srcport_end"`
}

type ProbingConfig struct {
    ProbeIntervalS    int `yaml:"probe_interval_s"`
    ProbeTimes        int `yaml:"probe_times"`
    InProbeIntervalMs int `yaml:"in_probe_interval_ms"`
    ProbeTimeoutMs    int `yaml:"probe_timeout_ms"`
}

type PerClientConfig struct {
    ClientID       Key32B64 `yaml:"client_id"`
    ClientName     string   `yaml:"client_name"`
    AdditionalCost float64  `yaml:"additional_cost"`
}
```

### 2.1 核心結構體

```go
type outbound struct {
    msgType protocol.MsgType
    payload []byte
}

// AFListener 管理某個 AF 上的 TCP + UDP 監聽
type AFListener struct {
    AF          types.AFName
    BindAddr    netip.Addr
    Port        uint16
    TCPListener net.Listener
    UDPConn     net.PacketConn
}

type AFConn struct {
    AF          types.AFName
    TCPConn     net.Conn
    Session     *crypto.Session        // handshake 後的 session key
    ConnectedAt time.Time
    RemoteIP    netip.Addr
    RemotePort  uint16
}

// ClientConn 代表 Controller 與單一 Client 的連線狀態
type ClientConn struct {
    ClientID    types.ClientID
    AFConns     map[types.AFName]*AFConn
    ActiveAF    types.AFName
    Synced      bool
    SendQueue   chan outbound
}

type Controller struct {
    cfg *config.ControllerConfig

    privateKey   [32]byte
    controllerID types.ControllerID

    mu    sync.Mutex
    state *ControllerState

    clients     map[types.ClientID]*ClientConn
    afListeners map[types.AFName]*AFListener

    // UDP sessions for communication channel (broadcast relay) keyed by receiver_index.
    udpSessionsByIndex map[uint32]*crypto.Session
    // Anti-replay: per-peer last seen TAI64N for handshake timestamp check.
    lastTAI64NByPeer   map[types.ClientID][12]byte

    // Debounce timers
    newClientTimer    *time.Timer
    newClientMaxTimer *time.Timer
    topoTimer         *time.Timer
    topoMaxTimer      *time.Timer
}
```

### 2.2 Controller Goroutines

```
Controller 啟動後的 goroutine 拓撲:

main goroutine
 │
 ├─ [per-AF] tcpAcceptLoop(af)          // 接受 TCP 連線
 │   └─ [per-conn] handleTCPConn(conn)  // 握手 → 讀取訊息迴圈
 │
 ├─ [per-AF] udpReadLoop(af)            // 讀取 UDP broadcast 封包
 │
 ├─ [per-client] clientSendLoop(client) // 從 SendQueue 取訊息，透過 active AF 的 TCP 發送
 │
 ├─ offlineChecker()                    // 定期掃描 LastSeen，超時則移除 Client
 │
 └─ signalHandler()                     // （cmd 層）處理 SIGTERM/SIGINT 優雅關閉
```

| Goroutine | 數量 | 職責 |
|-----------|------|------|
| `tcpAcceptLoop` | N (每個 AF 一個) | `net.Listener.Accept()` 迴圈，每個新連線 spawn `handleTCPConn` |
| `handleTCPConn` | M (每條 TCP 連線) | 執行 Noise IK handshake → 識別 ClientID → 進入訊息讀取迴圈，處理 ClientRegister / RouteUpdateBatch / ProbeResults 等 |
| `udpReadLoop` | N (每個 AF 一個) | 讀取 UDP 封包，解密後分發 MulticastForward（轉發給其他 Client） |
| `clientSendLoop` | K (每個已連線 Client 一個) | 從 `SendQueue` channel 取出訊息 → 透過 active AF 的 TCP 連線加密發送（不做重傳；重新同步由 enqueue 時處理） |
| `offlineChecker` | 1 | 每隔固定間隔掃描 `LastSeen`；若該 Client 仍有任一條 active TCP 連線，視為 online 並更新 LastSeen；否則超過 `ClientOfflineTimeout` 則移除並重算路由 |

### 2.3 Controller 關鍵流程

#### 收到 ClientRegister

```
handleTCPConn:
  1. Noise IK handshake → 得到 session key + ClientID
  2. 讀取 ClientRegister 訊息
  3. mu.Lock()
  4. 更新/建立 ClientInfo（Endpoints, LastSeen）
  5. 設定 AFConn, 判斷 ActiveAF（最早連線的 AF）
  6. 若此 AF 是 ActiveAF → 產生 ControllerState 快照推入 SendQueue, 標記 Synced=true
  7. 更新 LastClientChange, 重設 newClientTimer (sync_new_client_debounce)
  8. mu.Unlock()
  9. 進入訊息讀取迴圈
```

#### State Mutation（full-replace 推送）

```
handleTCPConn 收到 RouteUpdateBatch / ProbeResults:
  1. mu.Lock()
  2. 修改 ControllerState（更新 RouteTable / LatencyMatrix）
  3. 序列化 ControllerStateUpdate（FullReplace=true, State=snapshot）
  4. for each client where Synced==true:
       try enqueue update to SendQueue
       if queue full: mark unsynced → drain queue → enqueue one full snapshot (resync)
  5. mu.Unlock()
```

#### 全量推送

```
觸發: 新 Client 連入 / TCP 重連 / Active AF 切換

  1. mu.Lock()
  2. snapshot = serialize(ControllerState)
  3. enqueue:
       - 初次/切換 active AF: MsgControllerState(snapshot)
       - 其他重新同步: MsgControllerStateUpdate{FullReplace=true, State=snapshot}
  4. client.Synced = true
  5. mu.Unlock()
```

#### Topology Update（收到 ProbeResults 後）

```
handleProbeResults:
  1. mu.Lock()
  2. 更新 LatencyMatrix[src][dst]（選擇 priority 低 → latency_mean 低的 AF）
  3. 重設 topoTimer/topoMaxTimer (topology_update_debounce / topology_update_debounce_max)
  4. mu.Unlock()

topoTimer / topoMaxTimer 到期:
  1. mu.Lock()
  2. 對 LatencyMatrix 套用 AdditionalCost 加權:
     cost[src][dst] = latency[src][dst] + AdditionalCost[dst]
  3. FloydWarshall(加權後的 cost matrix) → RouteMatrix
  4. 推送 full-replace ControllerStateUpdate 給所有 Synced Client
  6. mu.Unlock()
```

---

## 3. Client 架構

### 3.0 Client 配置

```go
type ClientConfig struct {
    PrivateKey Key32B64 `yaml:"private_key"`
    BridgeName string   `yaml:"bridge_name"`

    ClampMSSToMTU     bool `yaml:"clamp_mss_to_mtu"`
    NeighSuppress     bool `yaml:"neigh_suppress"`
    BroadcastPPSLimit int  `yaml:"broadcast_pps_limit"`

    AFSettings map[types.AFName]*ClientAFConfig `yaml:"address_families"`

    FDBDebounceMs    int      `yaml:"fdb_debounce_ms"`
    FDBDebounceMaxMs int      `yaml:"fdb_debounce_max_ms"`
    InitTimeout      Duration `yaml:"init_timeout"`

    NTPServers        []string `yaml:"ntp_servers"`
    NTPResyncInterval Duration `yaml:"ntp_resync_interval"`

    APIUnixSocket string `yaml:"api_unix_socket"`
}

type ClientAFConfig struct {
    Name              types.AFName `yaml:"name"`
    Enable            bool         `yaml:"enable"`
    BindAddr          Addr         `yaml:"bind_addr"`
    ProbePort         uint16       `yaml:"probe_port"`
    CommunicationPort uint16       `yaml:"communication_port"`

    VxlanName         string `yaml:"vxlan_name"`
    VxlanVNI          uint32 `yaml:"vxlan_vni"`
    VxlanMTU          int    `yaml:"vxlan_mtu"`
    VxlanDstPort      uint16 `yaml:"vxlan_dstport"`
    VxlanSrcPortStart uint16 `yaml:"vxlan_srcport_start"`
    VxlanSrcPortEnd   uint16 `yaml:"vxlan_srcport_end"`

    Priority    int32               `yaml:"priority"`
    Controllers []ControllerEndpoint `yaml:"controllers"`
}

type ControllerEndpoint struct {
    PubKey Key32B64 `yaml:"pubkey"`
    Addr   AddrPort `yaml:"addr"`
}
```

### 3.1 核心結構體

```go
type Client struct {
    cfg *config.ClientConfig

    privateKey [32]byte
    clientID   types.ClientID

    mu                  sync.Mutex
    controllers         map[types.ControllerID]*ControllerConn
    controllerEndpoints map[types.ControllerID]map[types.AFName]netip.AddrPort
    authority           *types.ControllerID

    afRuntime map[types.AFName]*AFRuntime

    bridgeName string
    vxlanDevs  map[types.AFName]*VxlanDev
    tap        *TapDevice

    tapInjectCh  chan []byte
    fdbNotifyCh  chan struct{}
    authNotifyCh chan struct{}
}

type ControllerConn struct {
    ControllerID types.ControllerID
    AFConns      map[types.AFName]*ClientAFConn
    ActiveAF     types.AFName            // 收到 MsgControllerState 的那個 AF

    mu     sync.Mutex
    sendMu sync.Mutex
    Synced bool
    View   *ControllerView
}

type ControllerView struct {
    Raw *pb.ControllerState

    ClientsByID map[types.ClientID]*pb.ClientInfo
    Latency     map[types.ClientID]map[types.ClientID]*pb.SelectedLatency
    Route       map[types.ClientID]map[types.ClientID]*pb.RouteEntry
    RouteTable  []*pb.RouteTableEntry
}

type ClientAFConn struct {
    AF        types.AFName
    TCPConn   net.Conn
    Session   *crypto.Session
    Connected bool
}

type VxlanDev struct {
    AF          types.AFName
    Name        string
    VNI         uint32
    MTU         int
    BindAddr    netip.Addr
    DstPort     uint16
    SrcPortStart uint16
    SrcPortEnd   uint16
}
```

### 3.2 Client Goroutines

```
Client 啟動後的 goroutine 拓撲:

main goroutine
 │
 ├─ ntpSyncLoop()                              // 定期 NTP 校時
 │
 ├─ initDevices()                              // 建立 bridge, vxlan, tap-inject (一次性)
 │
 ├─ [per-controller, per-AF] tcpConnLoop(ctrl, af)   // TCP 連線 + 重連迴圈
 │   └─ tcpRecvLoop(ctrl, af)                        // 讀取 Controller 推送的訊息
 │
 ├─ [per-AF] commUDPReadLoop(af)               // 監聽 communication channel UDP，接收 MulticastDeliver
 │
 ├─ [per-AF] probeUDPReadLoop(af)              // 監聽 probe channel UDP：handshake + ProbeRequest/Response
 │
 ├─ neighWatchLoop()                           // netlink 監聽鄰居表變更 + debounce
 │
 ├─ tapReadLoop()                              // 從 tap-inject fd 讀取 broadcast 封包 → 上傳 Controller
 │
 ├─ tapWriteLoop()                             // 從 channel 取封包 → 寫入 tap-inject fd
 │
 ├─ fdbReconcileLoop()                         // RouteMatrix/RouteTable 變更時重算 FDB 並寫入 kernel
 │
 ├─ authoritySelectLoop()                      // init_timeout 後選擇權威 Controller，後續持續監控切換
 │
 └─ apiServerLoop()                            // 暴露 Unix socket REST API (讀寫 bind_addr 等)
```

| Goroutine | 數量 | 職責 |
|-----------|------|------|
| `ntpSyncLoop` | 1 | 定期向 `ntp_servers` 校時，更新 `TimeOffset` |
| `tcpConnLoop` | C*A (每個 Controller 的每個 AF) | 建立 TCP → Noise IK handshake → 發送 ClientRegister → 啟動 `tcpRecvLoop`。斷線後指數退避重連 |
| `tcpRecvLoop` | C*A | 讀取 TCP 訊息（ControllerState / ControllerStateUpdate），更新 `ControllerView`。收到全量更新時切換 `ActiveAF` |
| `commUDPReadLoop` | A (每個 AF) | 讀取 communication channel 的 UDP 封包（解密後的 MulticastDeliver）→ 注入 tap-inject |
| `probeUDPReadLoop` | A (每個 AF) | 讀取 probe channel 的 UDP 封包：Noise handshake（無 session 時）+ ProbeRequest/ProbeResponse |
| `neighWatchLoop` | 1 | 透過 netlink 訂閱 `RTM_NEWNEIGH` / `RTM_DELNEIGH`，debounce 後上報所有 Controller |
| `tapReadLoop` | 1 | 從 tap-inject 讀取 broadcast 封包 → rate limit(`broadcast_pps_limit`) → 優先上傳權威 Controller，否則 fallback 任一可達 Controller（MulticastForward） |
| `tapWriteLoop` | 1 | 從 channel 取出 Controller relay 來的 broadcast 封包（MulticastDeliver）→ 寫入 tap-inject 注入 bridge |
| `fdbReconcileLoop` | 1 | 監聽 `RouteMatrix` 或 `RouteTable` 變更通知 (channel) → 重新計算 FDB → diff 寫入 kernel (`netlink`) |
| `authoritySelectLoop` | 1 | `init_timeout` 後選擇權威 Controller；之後當 Controller Synced 狀態變化時重新評估 |
| `apiServerLoop` | 1 | Unix socket REST API（JSON），暴露 bind_addr 讀寫等操作 |

API（listen on `api_unix_socket`）:
- `GET /v1/af/{af}` → `{"af":"v4","bind_addr":"192.0.2.1"}`
- `PUT /v1/af/{af}/bind_addr` body: `{"bind_addr":"192.0.2.2"}`

### 3.3 Client 關鍵流程

#### 啟動序列

```
1. 載入配置 (YAML)
2. ntpSyncLoop() 啟動（`ntp_resync_interval`），首次校時
3. initDevices():
   a. 建立/確認 bridge
   b. 每個 AF: 建立 vxlan device, attach to bridge, hairpin on, learning off, neigh_suppress 視配置決定
   c. 建立 tap-inject, attach to bridge, learning off, neigh_suppress 視配置決定
   d. 若 clamp_mss_to_mtu: 寫入 nftables 規則
   e. 開啟 tap-inject（建立 `TapDevice`）
4. 每個 enabled AF: 建立 AFRuntime sockets（comm/probe UDP）並啟動 `commUDPReadLoop` / `probeUDPReadLoop`
5. 啟動 tapReadLoop, tapWriteLoop
6. 啟動 neighWatchLoop（debounce 後上報 RouteUpdateBatch）
7. 啟動 fdbReconcileLoop（等待權威 Controller）
8. 啟動 authoritySelectLoop: 等待 init_timeout → 選擇權威 Controller → 開始寫入 FDB
9. 啟動所有 per-controller, per-AF tcpConnLoop（TCP 連線 + 重連 + 收包）
```

#### 權威 Controller 選擇

```
selectAuthority():
  candidates = [ctrl for ctrl in Controllers if ctrl.Synced == true]
  if len(candidates) == 0: return nil

  sort candidates by:
    1. ClientCount DESC
    2. LastClientChange ASC (越早越穩定)
    3. ControllerID ASC (bytes 比較)

  return candidates[0]
```

#### Probe 執行（收到 ControllerProbeRequest）

```
tcpRecvLoop 收到 ControllerProbeRequest:
  1. 檢查是否來自權威 Controller → 否則忽略
  2. spawn runProbe(request):
     for i := 0; i < probe_times; i++:
       for each peer in knownClients:
         for each AF where self.enabled && peer.enabled:
           send ProbeRequest{batch_id, seq=i, probe_id} via probe channel UDP
       sleep(in_probe_interval_ms)
     wait(probe_timeout_ms) for remaining responses
     aggregate per-peer/per-AF results（latency mean/std + loss based on seq stats）→ ProbeResults
     send ProbeResults to ALL Controllers（透過各 ControllerConn 的 active AF 或任一可用 AF TCP）
```

#### FDB 寫入

```
fdbReconcileLoop (觸發: 收到 ControllerState/ControllerStateUpdate、authority 切換):
  1. 若 authority == nil → skip
  2. view = controllers[authority].View（由 protobuf ControllerState 建立）
  3. desiredFDB = {}
  4. for each rte in view.RouteTable:
       owner = pickOwner(me, rte, view)  // Owners 中 latency 最小且未過期者；若無 latency 則 deterministic fallback
       re = view.Route[me][owner]
       if re == nil/unreachable: continue
       nexthop = re.NexthopClientId; af = re.AfName
       dstIP = endpointIP(nexthop, af)
       desiredFDB[mac] = {dev: vxlanDevs[af], dst: dstIP}
  5. diff(CurrentFDB, desiredFDB):
       - 新增/變更: bridge fdb replace
       - 刪除: bridge fdb del
       - 若 MAC 仍存在於 RouteTable 但本次快照暫時沒有可用 next-hop，保留既有 FDB entry 避免短暫黑洞
  6. CurrentFDB = desiredFDB
```

---

## 4. Crypto 模組 (`pkg/crypto`)

### 4.1 Session

```go
type Session struct {
    LocalIndex   uint32
    RemoteIndex  uint32
    SendKey      [32]byte
    RecvKey      [32]byte
    SendCounter  atomic.Uint64    // nonce counter (發送方向)
    RecvCounter  uint64           // 上次驗證的 counter (TCP: 嚴格遞增)
    RecvWindow   *SlidingWindow   // UDP only: 2048-bit sliding window 防 replay
    PeerID       ClientID         // 握手後關聯的對端 ID
    CreatedAt    time.Time
}

type SlidingWindow struct {
    bitmap  [256]byte  // 2048 bits
    top     uint64     // 窗口最高 counter
}
```

### 4.2 Noise IK Handshake

```go
// Initiator 端
func HandshakeInitiate(
    localStatic  [32]byte,  // private key
    remoteStatic [32]byte,  // peer public key
) (initMsg []byte, state *HandshakeState, err error)

// Responder 端
func HandshakeRespond(
    localStatic [32]byte,
    initMsg     []byte,
    allowedKeys []ClientID,  // Controller: Allowed_Clients; Client: controller pubkeys
) (respMsg []byte, session *Session, err error)

// Initiator 完成
func HandshakeFinalize(
    state   *HandshakeState,
    respMsg []byte,
) (session *Session, err error)
```

---

## 5. Protocol 模組 (`pkg/protocol`)

### 5.1 TCP Framing

```go
// TCP 訊息格式: [4B length][1B msg_type][NB encrypted_payload]
// length = 1 + N

func WriteTCPMessage(conn net.Conn, session *Session, msgType MsgType, payload []byte) error
func ReadTCPMessage(conn net.Conn, session *Session) (msgType MsgType, payload []byte, err error)
```

### 5.2 UDP Packet

```go
// UDP 封包格式: [1B msg_type][4B receiver_index][8B counter][NB encrypted_payload]

func WriteUDPPacket(conn net.PacketConn, addr net.Addr, session *Session, msgType MsgType, payload []byte) error
func ReadUDPPacket(data []byte, findSession func(uint32) *Session) (msgType MsgType, payload []byte, peerID ClientID, err error)
```

### 5.3 MsgType 定義

```go
type MsgType byte

const (
    // Handshake
    MsgHandshakeInit MsgType = 0x01
    MsgHandshakeResp MsgType = 0x02

    // Client → Controller (TCP)
    MsgClientRegister    MsgType = 0x10
    MsgRouteUpdate       MsgType = 0x11
    MsgProbeResults      MsgType = 0x12

    // Controller → Client (TCP)
    MsgControllerState       MsgType = 0x20  // 全量
    MsgControllerStateUpdate MsgType = 0x21  // full-replace（見 ControllerStateUpdate.FullReplace）
    MsgControllerProbeRequest MsgType = 0x22

    // Broadcast relay (UDP, communication channel)
    MsgMulticastForward  MsgType = 0x30  // Client → Controller
    MsgMulticastDeliver  MsgType = 0x31  // Controller → Client

    // Probe (UDP, probe channel)
    MsgProbeRequest      MsgType = 0x40
    MsgProbeResponse     MsgType = 0x41
)
```

---

## 6. IPC / 通訊流程總覽

### 6.1 Client ↔ Controller (TCP Communication Channel)

```
Client                                    Controller
  │                                           │
  │──── TCP connect ─────────────────────────>│  tcpAcceptLoop
  │                                           │
  │──── HandshakeInit ───────────────────────>│
  │<─── HandshakeResp ───────────────────────│  → session key established, ClientID known
  │                                           │
  │──── ClientRegister ──────────────────────>│  → Controller 更新 ClientInfo
  │<─── ControllerState (全量) ──────────────│  → Client 標記 Synced=true
  │                                           │
  │──── RouteUpdateBatch ────────────────────>│  (持續, debounced)
  │<─── ControllerStateUpdate (full-replace) ─│  (持續)
  │                                           │
  │<─── ControllerProbeRequest ──────────────│  (觸發 probe)
  │──── ProbeResults ────────────────────────>│  (probe 完成後)
  │                                           │
```

### 6.2 Client ↔ Client (UDP Probe Channel)

```
Client A                                  Client B
  │                                           │
  │  (若無 session key，先 handshake)          │
  │──── HandshakeInit ───────────────────────>│
  │<─── HandshakeResp ───────────────────────│
  │                                           │
  │──── ProbeRequest {batch_id, seq, probe_id, src_ts} ───────>│
  │<─── ProbeResponse {batch_id, seq, probe_id, dst_ts} ───────│
  │                                           │
  │  計算單向延遲 = dst_timestamp - src_timestamp
```

### 6.3 Broadcast Relay (UDP Communication Channel)

```
Client A          Controller           Client B, C, D...
  │                   │                      │
  │ (tap-inject read) │                      │
  │── MulticastFwd ──>│                      │
  │                   │── MulticastDeliver ─>│ (寫入 tap-inject)
  │                   │── MulticastDeliver ─>│
  │                   │  (skip Client A)     │
```

---

## 7. Debounce 機制

### 7.1 Client: 鄰居表變更 (fdb_debounce)

```go
// neighWatchLoop 中:
// 收到 netlink 事件 → 累積到 pendingChanges
// 重設 debounceTimer (fdb_debounce_ms)
// 若 debounceMaxTimer (fdb_debounce_max_ms) 未啟動則啟動
//
// debounceTimer 到期 或 debounceMaxTimer 到期:
//   flush pendingChanges → 上報所有 Controller
//   重設兩個 timer
```

### 7.2 Controller: 新 Client (sync_new_client_debounce)

```go
// 收到新 Client 連線:
// 重設 newClientTimer (sync_new_client_debounce)
// 若 newClientMaxTimer (sync_new_client_debounce_max) 未啟動則啟動
//
// newClientTimer 到期:
//   對所有 Client 發送 ControllerProbeRequest
//
// newClientMaxTimer 到期:
//   對所有 Client 發送 ControllerProbeRequest（避免持續被新 client 連入延後）
```

### 7.3 Controller: Topology Update (topology_update_debounce)

```go
// 收到 ProbeResults:
// 更新 LatencyMatrix
// 重設 topoTimer (topology_update_debounce)
// 若 topoMaxTimer (topology_update_debounce_max) 未啟動則啟動
//
// topoTimer/topoMaxTimer 到期:
//   FloydWarshall → RouteMatrix
//   推送 ControllerStateUpdate
```

---

## 8. 多 AF 連線管理

### Controller 側

- 同一 `ClientID` 可能有多條 AF 連線（如 v4 + v6）
- `ClientConn.ActiveAF` = 最早建立連線的 AF
- Active AF 斷線 → 切換到剩餘最早連線的 AF → 對該 AF 發送全量更新
- 非 active AF 斷線 → 僅移除 `AFConn`，不影響推送

### Client 側

- 對每個 Controller 維護多條 AF 連線
- 收到某 AF 的全量更新 → 將該 AF 設為 `ActiveAF`
- 上報訊息（RouteUpdateBatch / ProbeResults）優先使用 `ActiveAF` 的 TCP 連線；若 ActiveAF 不可用則 fallback 任一可用 AF
- 某 AF 斷線 → 自動重連（指數退避），不影響其他 AF

---

## 9. 關鍵 Channel 設計

```go
// Controller: Per-Client 發送佇列
SendQueue chan outbound  // buffered, 容量可配置 (e.g. 256)

// Client: broadcast 注入佇列
tapInjectCh chan []byte  // tapWriteLoop 從此 channel 讀取並寫入 tap fd

// Client: FDB 重算通知
fdbNotifyCh chan struct{}  // RouteMatrix 或 RouteTable 變更時發送通知

// Client: 權威變更通知
authNotifyCh chan struct{}  // Synced 狀態變化時觸發重新評估
```

---

## 10. 外部依賴

| 依賴 | 用途 |
|------|------|
| `golang.org/x/crypto` | X25519, ChaCha20-Poly1305 |
| `google.golang.org/protobuf` | Protobuf 序列化 |
| `github.com/vishvananda/netlink` | Netlink: bridge fdb, 鄰居表監聯, vxlan/bridge device 管理 |
| `gopkg.in/yaml.v3` | YAML 配置解析 |
| `github.com/beevik/ntp` | NTP 校時 |

---

## 11. Graceful Shutdown

```
收到 SIGTERM/SIGINT:
  1. 停止接受新 TCP 連線
  2. 關閉所有 debounce timer
  3. Controller: 關閉所有 Client SendQueue → clientSendLoop 結束 → 關閉 TCP
  4. Client: 關閉 tap fd, 清理 FDB entries, 移除 nftables 規則
  5. 關閉 vxlan devices (可選，留給 OS 清理)
  6. 退出
```
