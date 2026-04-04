# VXLAN Controller:

一個 vxlan 控制器,分成 Controller 和 Client 兩個角色

目的: 讓所有 client 使用 vxlan 組成 L2 大內網,類似 EVPN 。
由 Client 蒐集本地的 mac address 和 local IP(用來做 ARP/NA 代答) 發給 Controller , Controller 計算 L2路由分發 給 Client ,寫入 linux kernel fdb

類似 VXLAN-EVPN ，但 frr 遲遲不支援 ipv6 ，所以想自己搓一個

### Configuration

Client 配置(client.conf）:
* private_key：私鑰，兼任 id (client_id=公鑰) 和加密。
    * 使用者可以用 wg genkey 和 wg pubkey 生成該值填入 config
    * 內部表示為 fixed byte array ([u8; 32])，設定檔中以 base64 編碼儲存（WireGuard 風格）
    * 加密方案仿照 **WireGuard Noise IK pattern**：
        * X25519 ECDH（static + ephemeral）推導 session key pair
        * ChaCha20-Poly1305 對稱加密，counter-based nonce
    * 所有節點間通訊使用 session key 加密
    * probe channel: 類似 WireGuard，如果本地沒有該 peer 的 session key 就發起 handshake，任何一方都可以發起，完成後拿到 session key 進行通訊
    * 收到 handshake，如果成功就建立 session key；如果本地已有 key 就替換（應對對端重啟）。若攻擊者無 privkey 則握手失敗，不影響現有通訊
    * 每次 communication channel（TCP）連線時握手，建立 session key，同時關聯對應的 client_id
    * broadcast channel（UDP）復用同一 port 上 TCP 握手建立的 session key，透過 receiver_index 識別 session
* bridge_name: 要監控 FDB 變更的 Linux 橋接器名稱(例如「br-vxlan」)僅處理此橋接器及其從屬連接埠上的 FDB 事件
* clamp_mss_to_mtu: true / false
* neigh_suppress: true / false: 是否在 VXLAN device 和 tap-inject 上啟用 `neigh_suppress`
    * 具體行為：bridge flood ARP/NS 到某個 port 時，若該 port 啟用了 `neigh_suppress` 且本地鄰居表有答案，bridge 不將 ARP/NS 送往該 port，改為直接生成 reply 回給發問者
    * 啟用時需要同時對 VXLAN device 和 tap-inject 都設定：
        * VXLAN device：阻止 ARP/NS 經由 vxlan data plane 轉發出去
        * tap-inject：阻止 ARP/NS 被 Client 讀走後上傳 Controller relay 給所有人
        * 兩者都設才能確保 ARP/NS 完全不外送
    * 鄰居表內容完全由 Controller 下發（步驟 14-16），不依賴 bridge 自學習
    * **啟用（on）**:
        * 優點：大幅減少 broadcast 流量。ARP/ND 是最常見的 broadcast，啟用後在本地直接代答，不需經過 Controller relay，降低延遲和頻寬開銷
        * 缺點：依賴 Controller 鄰居表的完整性。若遠端新裝置剛上線、尚未產生任何封包，Controller 還沒有它的鄰居資訊，此時 ARP/NS 會被 suppress 但無法代答，導致查詢失敗，直到 Controller 下發該裝置的鄰居資訊後才能解析
    * **關閉（off）**:
        * 優點：ARP/NS 照常廣播到所有節點，遠端新裝置即使靜默上線、尚未被 Controller 收錄，也能透過廣播讓對方收到 ARP/NS 後回應，立刻建立連線。對 Controller 鄰居表的時效性要求較低，容錯性更好
        * 缺點：所有 ARP/ND 請求都走 tap-inject → UDP 上傳 Controller → relay 給所有 Client 的完整路徑，broadcast 流量大，延遲高，尤其在節點數多的情況下開銷顯著
* AddressFamilySpecficSettings: map<af_name, per_af_conf>
    * v4:
        * name: v4
        * enable:true/false
        * local bind addr
        * probe port
        * communication port
        * vxlan_name
        * vxlan vni
        * vxlan mtu
        * priority
          * 給 controller 計算路由時參考
        * controllers (pubkey,addr:port)[](可以有多個 controller)
    * v6:
        * name: v6
        * enable:true/false
        * local bind addr
        * probe port
        * communication port
        * vxlan_name
        * vxlan vni
        * vxlan mtu
        * priority
            * 給 controller 計算路由時參考
        * v6 controllers (pubkey,addr:port)[](可以有多個 controller)
            * 若有多個( 例如 v4+v6 雙線上網)使用相同 pubkey ，視為同一個 controller。
            * 此時會建立 v4+v6 兩條通訊連結，目的是讓 controller 得知 client 的 v4+v6 地址。(或更多 af)
            * **多 AF 通訊連結選擇機制**:
                * 每個 controller 的每條 AF 連線各自維護一個 `active` 狀態
                * **Controller 視角**: 同一 client_id 的多條 AF 連線中，使用**最早建立連線**的一條作為 active communication channel
                    * tcp 建立 → 握手加密（同時得知 client_id）→ 發送全量更新
                    * 若 active 連線斷線，Controller 切換到剩餘連線中**最早連線**的 AF，對其發送全量更新（及後續 `ControllerStateUpdate` full-replace 更新）
                * **Client 視角**: 每當某個 AF 收到該 Controller 的全量更新，就自動將該 Controller 的 active communication channel 切換到這個 AF
                    * Client 上報訊息（MAC/鄰居/ProbeResults 等）時，使用當前 active AF 的 communication channel
                    * 某條 AF 的 TCP 斷線後自動嘗試重連，不影響其他 AF 的連線
                    * 重連成功後走正常流程（握手 → Controller 判斷是否設為 active → 若是則發送全量更新 → Client 收到後切換 active）
    * asia_v4:
        * 目前假設只有 v4+v6 兩個 af ，但使用 map 或 dict，可以允許更多 af
        * 設計原則是
          1. client 有多個 af
          2. controller 知道每個 client 有哪些 af
        * 所有**相同 af 內的 client 會 full mesh 互連**
        * 所以搭配多 af 設計，可以組合出更多變的用法。
          * 最基本的用法就只有 v4 +v6 ，部分節點 v4 only 部分節點 v6 only ，靠 v4+v6 雙線節點中轉
          * 還可以分出這些 af:
              * asia_v4
              * europe_v4
              * america_v4
              * 以及一個 backbone_v4 連接所有區域
          * 這樣子 asia_v4 節點就不會和 europe_v4 互聯，必須經過擁有 backbone_v4 屬性的節點
* 其中 local bind addr 允許動態變換(對應浮動IP的情況)
    * 暴露 API 讀寫。搭配一個 syncer ，讀取網卡 IP 變化，對比，更新到 client 裡面
    * 有人呼叫更新時，新建 socket 綁定新 IP,通訊切過去,釋放舊 socket
* fdb_debounce_ms: 本地 FDB/鄰居變更事件的 debounce 靜默期（預設值：500）。當偵測到 MAC/鄰居變更後，等待此時間內無新變更才觸發上報給 Controller
* fdb_debounce_max_ms: debounce 的最大等待時間（預設值：3000）。從第一次變更算起，即使持續有新變更，超過此時間也會強制 flush 上報，避免持續變更導致遲遲不發送
* init_timeout：初始化模式下等待的時間（以秒為單位），之後才會選擇權威控制器，並編寫 FDB 條目（預設值：10）。這允許所有控制器穩定運行client_count，last_client_change_timestamp 之後客戶端才會提交權威選擇。
* ntp_servers[]: NTP server 列表，校準本機時間的誤差
* ntp_resync_interval: NTP 重新校時的週期（預設值：23h）。設定檔可用 `23h` / `30m` 之類的 duration 字串
* broadcast_pps_limit: 上傳 broadcast/multicast（tap-inject 讀到的封包）到 Controller 的速率上限（單位：pps，預設值：2000）。可在 YAML 調整
* api_unix_socket: Client 提供本機管理 API 的 unix socket 路徑（RESTful + JSON）。空字串表示不啟用
    * `GET /v1/af/{af}`：查詢該 AF 的目前 `bind_addr`
    * `PUT /v1/af/{af}/bind_addr`：更新該 AF 的 `bind_addr`，Client 會重建 socket、重連 controllers，並更新 vxlan device local


Controller 配置:

* private_key：私鑰，兼任 ID 和加密。
    * 格式同 Client：內部 [u8; 32]，設定檔 base64 編碼
    * 加密方式同 Client：X25519 ECDH + ChaCha20-Poly1305
* AddressFamilySpecficSettings: map<af_name, per_af_conf>
    * v4:
        * name: v4
        * enable:true/false
        * local bind addr
        * communication port: 同一 port 同時 listen TCP（控制面）和 UDP（broadcast relay）。Controller 透過 Client TCP 連線的 remote IP 得知該 AF 下的 Client IP
        * vxlan vni
        * vxlan dstport
        * vxlan srcport-start, srcport-end
    * v6:
        * name: v6
        * enable:true/false
        * local bind addr
        * communication port: 同一 port 同時 listen TCP（控制面）和 UDP（broadcast relay）。Controller 透過 Client TCP 連線的 remote IP 得知該 AF 下的 Client IP
        * vxlan vni
        * vxlan dstport
        * vxlan srcport-start, srcport-end
            * id, dstport, srcports 在 controller 和所有 client 中必須完全相同
            * 因為 linux 不允許兩兩節點用各自的 port 通訊，要統一
            * 但未來專案可以擴展到非 vxlan 的場景，所以保留各自的 port 設定，戰未來
* ClientOfflineTimeout: Client 離線超過這麼久視為斷線,從路由表計算中移除。然後刪除其 Type-2 Route 條目並重新計算路由的持續時間（以秒為單位）（預設值：300）
* sync_new_client_debounce: 新客戶端連線後觸發 ControllerProbeRequest 事件前等待的秒數（預設值：2）
  * 如果在此期間有其他用戶端連接，計時器將重設
  * 必須滿足：sync_new_client_debounce > probe_times * in_probe_interval_ms + probe_timeout_ms
* sync_new_client_debounce_max: sync_new_client_debounce 的最大等待時間（預設值：10）。從第一次新客戶端連線算起，即使持續有新客戶端加入，超過此時間也會強制觸發 ControllerProbeRequest，避免被無限推遲
    * 目的: 每當新客戶端連線進來， controller 要發送 ControllerProbeRequest ， client 收到以後發送 Probe 測量延遲，讓 controller 重新計算路由表
    * 但剛啟動時，短時間有大量 client 同時加入，導致大量重複的 Probe
    * 所以要加一個延遲，確認一段時間都沒有新人加入，才發送 ControllerProbeRequest
* topology_update_debounce: 收到 ProbeResults 後等待的靜默期，期間無新 ProbeResults 才觸發 topology_update（預設值：1）
* topology_update_debounce_max: topology_update_debounce 的最大等待時間（預設值：5）。從第一次收到 ProbeResults 算起，即使持續有新結果進來，超過此時間也會強制執行 topology_update，避免被無限推遲
* probing:
    * probe_interval_s: 60
    * probe_times: 5
    * in_probe_interval_ms: 200
    * probe_timeout_ms: 1000
    * 限制:
        * Client 收到以後，需要按照 in_probe_interval_ms 間隔，總共發出 probe_times 個 probe ，每個 probe 最多等待 probe_timeout_ms
        * 所以總時間花費 = probe_times * in_probe_interval_ms + probe_timeout_ms
        * 必須保證單一 probe 的總時間花費不能超過 probe_interval_s 多留一秒當緩衝，所以有以下限制
        * probe_times * in_probe_interval_ms + probe_timeout_ms < (probe_interval_s - 1) * 1000.
* Allowed_Clients: [PerClientConfig]
    * PerClientConfig:
        * client_id: 公鑰，用來識別 Client
        * client_name: 純標記用，目前無實際功能
        * AdditionalCost: 經過此節點轉發時額外增加的成本（預設值：20）
            * 用途：在 LatencyMatrix 上加權後再計算 Floyd-Warshall，避免為了微小延遲差而繞路
            * 範例：

              假設三個節點 A、B、C，所有節點 `AdditionalCost=10`：

              | Path    | Latency | AdditionalCost | Cost | Win |
              |---------|---------|----------------|------|-----|
              | A→B→C   | 3ms     | 20             | 23   |     |
              | A→C     | 4ms     | 10             | 14   | O   |

              A→C 直連勝出。`AdditionalCost=10` 意味著：必須能省下 10ms，繞路才值得
            * 其他用法：
                * 流量昂貴的節點設定 `AdditionalCost=10000`，其他節點就不會經過它中轉，除非別條路線全部不可達
                * 全部節點都設定 `AdditionalCost=10000`，效果為無視延遲、全節點盡量直連，只有直連失敗才繞路

## 運作過程:

分成3個通道

1. data channel(udp via vxlan port): 實際的資料傳輸通道,明文傳輸
2. probe channel(udp via probe port): Client 之間發送 Latency Probe ,計算延遲。使用 X25519 ECDH shared secret + ChaCha20-Poly1305 加密
3. communication channel(communication port): Client - Controller 之間通訊，同一個 port 上同時使用 TCP 和 UDP
    * 使用 X25519 ECDH shared secret + ChaCha20-Poly1305 加密
    * TCP: 控制面訊息（可靠、有序）
        * ClientRegister（上報 client_id、各 AF 的 probe port / vxlan dstport）
        * 上報 local mac / neighbor
        * 下載 L2 路由
        * ControllerState / ControllerStateUpdate
        * ControllerProbeRequest / ProbeResults
    * UDP: 廣播封包轉發（盡力傳輸、低延遲）
        * 上傳廣播封包（MulticastForward，有 rate limit）
        * 下載廣播封包（MulticastDeliver）



## 實作細節:

0. 初始化時 Client 會使用 ntp_servers 校時，得知系統時間偏差。接下來所有時間計算都會套用修正。後續定時重新校正
1. 首先 Client 會使用 tcp(local bind addr:communication port --> controller addr:port ) 建立到**所有 Controller 的連線**，並選擇一個 Controller 作為權威控制器
    * Client 對所有 Controller 執行相同操作，並為所有控制器維護一個狀態，但只使用權威控制器的結果
    * 權威 Controller 選擇策略:
        * 候選池：只有 Synced = true 的控制器才有資格被選擇。Synced = false 的控制器排除
        * 主要標準：客戶端數量最高（連線的客戶端最多）
        * 平手決勝規則 1：最早的 last_client_change_timestamp（獎勵穩定的控制器-客戶連線；時間戳越小，穩定性越長）
        * 平手決勝規則 2：最低的 controller_id（以公鑰位元組比較確定性地打破平手）
2. Client 對所有 Controller 發送 ClientRegister，包含：
    * client_id (pubkey)
    * 每個啟用 AF 的資訊：probe port、vxlan dstport
    * （IP 不需要帶，Controller 從 TCP remote IP 得知）
3. Controller 返回 ControllerState ，自此 Client 和該 Controller 狀態同步
    * Client 此時拿到了其他所有 Client 的 pubkey 和 EndpointV4, EndpointV6
    * Client 標記該 Controller 為 Synced = true
4. Client 等待 init_timeout
    * 目的：讓所有 Controller 的 ControllerState 都穩定下來（client_count、last_client_change_timestamp）
    * init_timeout 到期後，從 Synced = true 的 Controller 中選擇權威 Controller
    * 選完權威後，才開始：寫入 FDB、回應 ControllerProbeRequest
5. Controller 會維護所有 client 的 tcp 連線地址作為 ClientIP,作為 Client info 的一部份
  * Client Info 有以下資訊:
    * ClientID(=PubKey)
    * EndpointV4
        * IP
        * probe port
        * vxlan dstport
    * EndpointV6
        * IP
        * probe port
        * vxlan dstport
    * LastSeen
    * Routes: client 上報的 mac address
      * Type: 模仿 EVPN Routes 。目前只實作 Type 2
      * IP
      * MAC
6. Client 建立 bridge、vxlan devices、tap-inject 後，開始監聽本地鄰居表變更，上報 mac+ip 給所有 Controller（與 probe 流程並行）
7. 接著 Controller 會等待 sync_new_client_debounce ，這期間沒有新客戶加入的話，執行 sync_new_client
8. Controller 執行 sync_new_client
    * 對所有 Client 發送 ControllerProbeRequest
      * 訊息包含
      * batch_id（Controller 產生的隨機唯一 ID，用於標識同一批 probe 結果；目前主要用於 debug/對齊，未做強制一致性用途）
      * probe_timeout_ms
      * probe_times
      * in_probe_interval_ms
    * 客戶端收到以後，**如果是自己的權威控制器發來的 ControllerProbeRequest ，執行 Probe**
9. Client 執行 Probe
    * Client 需要按照 in_probe_interval_ms 間隔，總共發出 probe_times 輪 probe
    * 透過 probe channel ，對所有的其他 Client 發送 ProbeRequest
      * 每個 probe UDP 封包都必須包含：
          * batch_id：同一批 probe 的 ID（來自 ControllerProbeRequest）
          * seq：本批次內的第幾輪（0..probe_times-1），用於統計丟包率
          * probe_id：每個封包唯一的隨機 ID（用於匹配 ProbeResponse；目前 Controller 不依賴此欄位）
          * src_timestamp（src_timestamp_unix_ns）
      * 如果自己的 v4+v6 enable ，且對面也支援，v4+v6 兩個 probe channel 都會發送（同一 batch_id、同一 seq，但每個封包有不同 probe_id）
    * 收到 ProbeRequest 以後，原路返回 ProbeResponse
      * ProbeResponse 會回帶 batch_id / seq / probe_id，並包含 dst_timestamp（dst_timestamp_unix_ns）
    * 收到 ProbeResponse 以後，和 src_timestamp 和 dst_timestamp 對比，得到「本地→遠端」的單向延遲
    * 當 probe_times 個 probe 都完成或超時以後，整合 ProbeResult 上傳給**所有 Controller**
        * 為什麼是**所有 Controller**呢?
        * 因為前面的設計「只處理權威控制器發來的 ControllerProbeRequest」
        * 如果所有控制器來的 ControllerProbeRequest 都處裡，會導致重複的 Probe 太多
        * 但是只回應給權威 Controller，非權威又拿不到結果。
        * 所以設計成 Client 只處理權威控制器發來的 ControllerProbeRequest
        * 但探測完的結果發給所有的 Controller ，讓全部 Controller 都有延遲資訊
        * 就算不是自己 issued ProbeRequest ，Controller 也會接受這個 ProbeResults
    * ProbeResults:
        * batch_id
        * source_client_id
        * probe_results: map< dst_client_id , ProbeResult>
        * ProbeResult< af_name, Result>:
            * v4:
                * latency_mean // INF_NUM if unreachable
                * latency_std
                * packet_loss
                * priority
            * v6:
                * latency_mean // INF_NUM if unreachable
                * latency_std
                * packet_loss
                * priority
            * 每個 af 的測量結果，包含 mean std loss priority ，目前只實作比較 priority 然後比較 mean
10. Controller 收到 ProbeResults 更新到 LatencyMatrix 裡面
    * 等待 topology_update_debounce 以後(如果等待期間有新的 ProbeResults 進來就重新等待，但最多等待 topology_update_debounce_max)，執行 topology_update
    * topology_update: 計算 RouteMatrix ，並發布 ControllerStateUpdate
    * LatencyMatrix:
        * [src_id][dst_id] = [ latency, af_name ]
        * src_id 回報的 src->dst 結果中，同時有所有 af 的 (v4/v6) 的延遲
        * 但實際上只會挑一條路走
            * 先實作這個: 挑選 priority 數值低的。若數值相同，挑選 latency_mean 低的
        * 被挑選的值會存入 LatencyMatrix[src_id][dst_id] ，latency 用於計算 RouteMatrix ，af_name 用於分發後， client 知道要走 v4/v6 哪條路
    * **AdditionalCost 加權**: 在計算 Floyd-Warshall 之前，先對 LatencyMatrix 套用 AdditionalCost。對於每一條邊 `LatencyMatrix[src][dst]`，其 cost 為：
        * `cost = latency + AdditionalCost[dst]`
        * 即經過目標節點轉發時，需要額外支付該節點的 AdditionalCost
        * 加權後的 cost matrix 才送入 Floyd-Warshall 計算最短路徑
    * RouteMatrix:
        * [src_id][dst_id] = [ nexthop_id, af_name( v4 or v6) ] or null(如果客戶端不可達)
        * af_name 是指 **src → nexthop 這一跳**的 AF，不是端到端的 AF
            * 例如 A→C 最短路徑為 A→B→C，A→B 走 v4，B→C 走 v6
            * RouteMatrix[A][C] = { nexthop=B, af=v4 }（A 到 B 這段走 v4）
            * RouteMatrix[B][C] = { nexthop=C, af=v6 }（B 到 C 這段走 v6）
        * 使用 Floyd-Warshall 在 AdditionalCost 加權後的 cost matrix 上計算所有客戶端對的最短路徑。
        * 不包含延遲訊息,僅包含下一跳路由決策。
11. 發布 ControllerStateUpdate
12. Client 收到 ControllerStateUpdate ，更新到對應的Controller 狀態
    * Client 能設定多個 Controller ，每個 Controller 都有其狀態
    * 但只會選擇一個 Controller 作為權威 Controller ，使用他的狀態
    * 客戶端在更改其權威控制器選擇時不會通知控制器。權威 Controller 的選擇是本地決策。
    * 理想情況所有 Controller 會得到相同結果，所以選誰都會通
13. Client 和 linux bridge 開始互動
    * 多個 VXLAN devices (one per AF), attached to the same Linux bridge.
    * 另外建立一個 **TAP device (tap-inject)**，掛到 bridge 上
        * 用途：Client 透過 `open /dev/net/tun`（TUN/TAP）取得 tap-inject 的 fd，直接 read/write 進行 broadcast capture 與 inject
        * read: bridge flood 的 broadcast/multicast 封包會送到 tap-inject，Client 從 fd 讀取
        * write: Client 將 Controller relay 的 broadcast/multicast 封包寫入 fd，注入 bridge
    * **Learning 策略**: 所有 FDB entry 由 Controller 管理，bridge 上所有 port 關閉自學習
        * vxlan device: `learning off` — 防止自學習和 Controller 分發的 FDB 衝突，且 hairpin 下自學習可能學到中轉節點的 IP 而非源節點
        * tap-inject: `learning off` — 否則 bridge 從 relay broadcast 中學到 MAC 指向 tap-inject，導致 unicast 走錯 port
        * 普通 slave（VM 的 tap/veth、eth0 等）: 保持 `learning on` — bridge 需要從本地 port 學習 MAC，才能正確將 unicast 送到對的本地設備
    * **Device Configuration**: 使用這個指令創建 vxlan device:
      ```bash
      ip link add {vxlan_name} type vxlan id {vni} local {bind_addr} ttl 255 dstport {port} srcport {port} {port} nolearning
      ip link set {vxlan_name} master {bridge_name}
      ip link set {vxlan_name} type bridge_slave hairpin on learning off neigh_suppress on  # neigh_suppress 視配置決定
      ip link set {vxlan_name} up
      ```
    * **TAP device for broadcast injection**:
      ```bash
      ip tuntap add dev tap-inject mode tap
      ip link set tap-inject master {bridge_name}
      ip link set tap-inject type bridge_slave learning off neigh_suppress on  # neigh_suppress 視配置決定
      # 不需要啟用 hairpin（vxlan FDB 無 broadcast entry，broadcast 不會從 vxlan 轉發出去）
      ip link set tap-inject up
      ```
      Client 透過 `open /dev/net/tun`（flag: IFF_TAP | IFF_NO_PI）取得 tap-inject 的 fd 進行讀寫
    * **Hairpin Mode**: bridge 上對 VXLAN interface 必須啟用 hairpin mode
        * 允許從一個 VXLAN 隧道接收的封包透過另一個 VXLAN 隧道轉送出去
        * （多跳路由所必需，例如 A→B→C，其中 B 在兩個 VXLAN 隧道之間轉送流量）。
    * 當 Client 收到 bind_addr update 時，需要呼叫 ip link 更新隧道的 local {bind_addr}
    * 當 clamp_mss_to_mtu 設定為 true 時，會新增以下 nftables 規則(vxlan-v4替換成實際名稱):
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
## Broadcast / Multicast 轉發機制

* **設計原則**: Broadcast/multicast 封包**完全不走 vxlan data plane**，一律由 Controller relay
    * FDB 中不寫入 broadcast/default entry（`00:00:00:00:00:00` 或 `ff:ff:ff:ff:ff:ff`），vxlan device 自然不會轉發 broadcast
    * 避免 hairpin + multi-AF 造成的 loop 問題
        * 例如 A(v4 only) → broadcast → B(v4 in, hairpin, v6 out) → C(v6 in, hairpin, v4 out) → B → loop
	* **流程**:
	    * tap-inject 掛在 bridge 上，bridge 的 broadcast/multicast 會自然 flood 到此 port
	    * Client 透過 tap-inject 的 fd 進行讀寫，一個 TAP device 同時解決 capture 和 inject
	    1. Client 從 tap-inject fd 讀取 broadcast/multicast 封包（bridge flood 過來的）
	        * 套用 rate limit（`broadcast_pps_limit`，單位 pps；超過上限的封包直接丟棄）
	    2. Client 透過 **UDP** communication channel 將封包上傳給 Controller（MulticastForward 訊息）
	    3. Controller 透過 **UDP** 轉發給**除了來源以外**的所有 Client（MulticastDeliver 訊息）
	    4. Client 收到後，將封包寫入 tap-inject fd，注入 bridge
	        * bridge flood 到所有 port，但 vxlan device FDB 中沒有 broadcast/default entry，查無匹配直接丟棄，不會送出 → 不會 loop
* **Client + Controller 同節點**: 完全支援
    * Client 透過 localhost TCP/UDP 連線到同節點的 Controller
    * Controller relay 時根據 source_client_id 跳過來源 Client，不會自己收到自己的 broadcast

## 配置檔格式

使用 **YAML** 格式。支援巢狀結構（AF settings map）且可讀性高。

## FDB 寫入邏輯

* 當 RouteMatrix 計算出 A→C nexthop=B, af=v4 時:
    * 在 A 的 vxlan-v4 device 上寫入: `bridge fdb replace <C_mac> dev vxlan-v4 dst <B_v4_addr>`
    * 只寫入被選中 AF 的 vxlan device，不寫其他 AF
* Broadcast/multicast MAC **不寫入** FDB（由 Controller relay 處理）

14. Client 透過 **netlink** 讀取並持續監聽本地的兩類資訊，上報給所有 Controller（步驟 6 已開始監聯，這裡是持續的過程）：
    * **鄰居表（neighbor table）**: 讀取 (mac, ip addr) 組合，用於 Controller 建立 RouteTable，也供 `neigh_suppress` 代答 ARP/NS
    * **FDB（forwarding database）**: 讀取 bridge 上本地 port 自學習到的 (mac, nil)（無 dst，代表本地 MAC），用於告知 Controller 哪些 MAC 在本 Client 上
    * 兩者皆透過 netlink 實現：啟動時先 **dump** 全量，之後持續 **subscribe** 變更事件（RTM_NEWNEIGH / RTM_DELNEIGH）
    * **Debounce 機制**：偵測到變更後不立即上報，而是等待 `fdb_debounce_ms`（預設 500ms）靜默期內無新變更才觸發上報，將多筆變更打包成一次發送
    * **Debounce 上限**：`fdb_debounce_max_ms`（預設 3000ms）從第一次變更算起，即使持續有新變更，超過此時間也強制 flush 上報，避免被無限推遲
    * 兩個 debounce 參數皆可在 Client 配置檔中調整
15. Controller 收到更新，同步到 Controller 的 RouteTable
    * RouteTable: 由以下三元組構成
        * mac
        * ip
        * map<client_id, ExpireTime>
    * 當相同的 ip+mac 歸屬多個 client_id 時，走 **LatencyMatrix 中延遲最小**的 client
    * 相當於 anycast
16. Controller 推送新版路由表給全部的 Client
17. Client 收到以後，結合 RouteMatrix + RouteTable 寫入 bridge fdb
    * **FDB 寫入需要兩者都就緒**:
        * RouteTable 提供「mac=X 在 Client C 上」
        * RouteMatrix 提供「到 Client C 走 nexthop=B, af=v4」
        * 合併後寫入: `bridge fdb replace <X> dev vxlan-v4 dst <B_v4_addr>`
    * RouteMatrix 或 RouteTable 任一方更新，都觸發重新計算 FDB

# 同步機制:

使用 Mutex + Per-Client 發送佇列，不引入 sequence number 或 per-client view state。

## Controller 端資料結構

* **ControllerState**: Controller 的全域狀態（ClientInfo、RouteMatrix、RouteTable 等），受一把 Mutex 保護
    * 任何時刻只有一個操作能持有鎖：state mutation、全量推送準備、更新推送準備
* **Per-Client 發送佇列**: 每個已連線 Client 持有一個帶 buffer 的發送佇列（send queue）
    * 所有推送給 Client 的訊息（全量或 `ControllerStateUpdate` full-replace 更新）先推入佇列
    * 由獨立的 per-client 發送 goroutine 從佇列取出，透過 TCP 照順序發送
    * 鎖只在「修改 state + 推訊息進佇列」期間持有，不涉及網路 I/O，持鎖時間為微秒級
* **synced 旗標**: 每個 Client 連線維護一個 `synced` 旗標，標記該 Client 是否已完成全量同步

## State Mutation（收到 client 上報、probe results 等）

1. 取得鎖
2. 修改 ControllerState
3. 序列化當前 ControllerState 的快照，包成 `ControllerStateUpdate { full_replace=true, state=snapshot }`
4. 將這個 update 推入所有 synced=true 的 Client 的發送佇列
5. 釋放鎖

## 全量推送

觸發時機：
* 新 client 連入
* TCP 斷線重連
* Active AF 斷線切換 — Controller 發現某 client 的 active AF 連線斷開時，從剩餘連線中選擇最早建立的 AF 作為新的 active channel，並 enqueue 一次新的全量快照（見下方流程）

流程：
1. 取得鎖
2. 將當前 ControllerState 的快照推入該 Client 的發送佇列
3. 將該 Client 標記為 synced=true
4. 釋放鎖

因為標記 synced=true 和釋放鎖在同一個臨界區內，後續的 mutation 一定會將後續的全量更新（`ControllerStateUpdate` full-replace）推入該 Client 的佇列，不會遺漏。

## 佇列滿的處理

如果某 Client 的發送佇列已滿（網路過慢），Controller 會將該 Client 標記為 synced=false、清空佇列，並**立即** enqueue 一筆 full-replace 的 `ControllerStateUpdate` 快照作為重新同步（避免在慢連線上持續累積陳舊更新）。

## TCP 斷線重連

* TCP 斷線重連成功後，重新經歷全量推送流程（取得鎖 → 快照推入發送佇列 → 標記 synced → 釋放鎖）
* **TCP 斷線不影響 Client 的上線狀態和路由**：
    * Controller 維護的 ClientInfo、RouteMatrix、RouteTable 不因 TCP 斷線而立即清除
    * 由 ClientOfflineTimeout 控制：只有超過此 timeout 仍無法重連，才視為該 Client 離線，清除其相關路由並重新計算
    * 這避免了短暫網路波動導致路由震盪（flapping）
* TCP 斷線期間的更新可能會丟失，但重連後的全量推送會補齊

## TCP 斷線偵測

Controller 端完全依賴 TCP 本身偵測 Client 離線，不需要額外的應用層心跳或 disconnect 訊息：

* **Client 正常關閉**: kernel 發送 FIN，Controller 的 `conn.Read()` 收到 `io.EOF`，觸發斷線處理
* **Client 崩潰/斷網**: TCP keepalive 超時或收到 RST，`conn.Read()` 返回 error，觸發斷線處理
* **TCP Keepalive 設定**: 在 `net.TCPConn` 上啟用 keepalive 並設定合理的探測間隔（例如 30s），確保在 `ClientOfflineTimeout`（預設 300s）之前能偵測到無回應的 Client
    ```go
    conn.SetKeepAlive(true)
    conn.SetKeepAlivePeriod(30 * time.Second)
    ```
* 斷線後 Controller 不立即清除 ClientInfo/路由，而是由 `ClientOfflineTimeout` 控制：超過 timeout 仍未重連才視為離線並清除路由，避免短暫網路波動造成路由震盪

## 保證

* TCP 保證資料流的順序和完整性
* Mutex 保證 state mutation、全量推送準備、更新推送準備三者互斥，不會有競爭
* 不需要 sequence number 或 per-client view state。發送佇列的 FIFO 順序保證 Client 先收到全量、再依序收到 full-replace 的更新，最終一致
* 鎖僅保護本地記憶體操作（修改 state + 推入佇列），不涉及網路 I/O，持鎖時間為微秒級


## 協議規格

### 訊息序列化

* **配置檔**: 使用 **YAML** 格式
* **網路訊息**: 使用 **Protocol Buffers (protobuf)** 序列化。所有訊息類型定義在 `.proto` 檔案中，透過 protoc 產生 Go 代碼

### TCP Framing

TCP 連線上使用 length-prefixed framing，格式如下：

```
[4 bytes: length (big-endian uint32)][1 byte: msg_type][N bytes: encrypted payload]
```

* `length` = `sizeof(msg_type) + sizeof(encrypted payload)` = `1 + N`
* `msg_type`: 訊息類型識別碼（例如 0x01=HandshakeInit, 0x02=HandshakeResp, 0x10=ClientRegister, ...）
* `encrypted payload`: 握手完成前為明文（僅 Handshake 訊息），握手完成後所有 payload 使用 ChaCha20-Poly1305 session key 加密

### Probe Channel Handshake

Probe channel（UDP）的 handshake 獨立於 TCP communication channel，仿照 **WireGuard Noise IK pattern**：

* 任何一方都可以發起 handshake（當本地沒有該 peer 的 session key 時）
* **HandshakeInit 訊息結構**（仿 WireGuard）：
    * `msg_type` (1B)
    * `sender_index` (4B): 發起方分配的 session index，用於後續封包中標識 session
    * `ephemeral_pubkey` (32B): 發起方的 ephemeral X25519 公鑰（明文）
    * `encrypted_static` (32B + 16B tag): 發起方的 static pubkey，用 ephemeral ECDH 結果加密
    * `encrypted_timestamp` (12B + 16B tag): TAI64N 時間戳，用於防止 replay
    * `mac` (16B): 整個訊息的 MAC
* **HandshakeResp 訊息結構**：
    * `msg_type` (1B)
    * `sender_index` (4B): 回應方分配的 session index
    * `receiver_index` (4B): 對應 HandshakeInit 的 sender_index
    * `ephemeral_pubkey` (32B): 回應方的 ephemeral X25519 公鑰
    * `encrypted_nothing` (0B + 16B tag): 確認金鑰推導正確
    * `mac` (16B)
* 雙方從兩組 ephemeral + static ECDH 結果推導出 session key pair（發送/接收各一）
* **重傳機制**: 發起方在未收到 HandshakeResp 時，按指數退避重傳 HandshakeInit（例如 1s, 2s, 4s），最多重傳 N 次
* 收到成功的 HandshakeResp 後建立 session key；若本地已有 session key 則替換（應對對端重啟）
* 握手失敗（對端無 private key）不影響既有 session key

### Nonce 與加密策略

仿照 WireGuard 的 nonce 管理：

* **ChaCha20-Poly1305** 對稱加密，nonce 為 **counter-based**（8 bytes little-endian counter + 4 bytes zero padding = 12 bytes nonce）
* 每個方向（發送/接收）維護獨立的 counter，從 0 遞增
* **同一個 session 會同時用於 TCP 與 UDP**，但為避免不同 transport 共用同一把 key 造成 nonce/counter 互相影響，會從 handshake 推導出的 send/recv master key 再做一次 domain separation：
    * `transport_key = HMAC(master_key, "vxlan-controller:"+transport)`，transport ∈ {"tcp","udp"}
    * TCP 與 UDP 各自維護獨立 counter（避免 nonce reuse）
* **TCP**: counter 隨訊息順序遞增，接收方驗證 counter 嚴格遞增（TCP 保證有序）
* **UDP**（probe + multicast）: counter 遞增發送，接收方使用 **sliding window**（仿 WireGuard，窗口大小 2048）防止 replay，允許亂序接收
* Counter 達到 `REJECT_AFTER_MESSAGES`（2^60）時，必須重新握手建立新 session

### UDP 封包格式（Probe 與 Multicast）

仿照 WireGuard transport data 格式：

```
[1 byte: msg_type][4 bytes: receiver_index][8 bytes: counter][N bytes: encrypted payload]
```

* `receiver_index`: 握手時對端分配的 session index，接收方用它查找對應的 session key
* `counter`: 即 nonce 的 counter 部分，用於解密及 replay 檢測
* `encrypted payload`: ChaCha20-Poly1305 加密的實際內容（protobuf 序列化的 ProbeRequest/ProbeResponse/MulticastForward/MulticastDeliver）

### TCP Communication Channel Handshake

TCP 連線建立後，同樣使用 WireGuard 風格的 Noise IK handshake（訊息結構同 Probe Channel Handshake），但透過 TCP framing 傳輸：

* 握手訊息使用 TCP framing（length-prefixed）包裝
* 握手完成後，雙方得到 session key pair + 關聯 client_id
* 後續所有 TCP payload 使用 session key + counter-based nonce 加密
* TCP 保證順序，所以接收方驗證 counter 嚴格遞增即可（不需 sliding window）


### Test
新增 `tests/` 資料夾，提供整合測試腳本：
* `tests/test_all.sh`：完整測試套件（會自動清理 namespace / bridge / veth）
* `tests/debug_setup.sh`：debug 用（不自動清理，方便手動觀察）

測試腳本會用 network namespace + veth 模擬 6 個 client 節點
以及 br-lan_v4: 192.168.47.0/24 和 br-lan_v6: fd87:4789::/64
1,2,3,4,10 加入 lan_v4
3,4,10,5,6 加入 lan_v6
1 2 3 4 5 6 是 Client
4,10 是 Controller

模擬部分 v4 only: 1 2
部分 v6 only: 5 6
部分雙線: 3 4 10
的情境

同時有
同時兼任 Client + Controller: 4
獨立擔任 Controller: 10
的場景

所有的 client 節點用 tc 發包時增加延遲模擬現實的，非對稱的延遲
確認確實會轉發

每個 client node 用 veth 連接一個 leaf ，確認所有的 leaf 都可以互 ping
每個 client node 的預設 local bind ip 都是 192.168.47.{id} 和 fd87:4789::{id}

#### 測試項目

##### 1. 基本連通性測試（neigh_suppress = false）
* 所有 leaf 互 ping，應直接全通
* 因為 neigh_suppress 關閉，ARP/NS 會正常 flood，雙方都能學到對方的 MAC 和 IP

##### 2. neigh_suppress = true 的行為差異
* A ping B：A 發出 ARP/NS，但此時 B 的鄰居表尚未被上報到 A 所在節點，neigh_suppress 無法代答，ARP/NS 需透過 broadcast relay 到 B
* 此時 A 已上報自己的鄰居資訊，但 B 尚未上報，所以 A→B 的第一次 ping 可能失敗（B 端的 neigh_suppress 無法代答 A 的 ARP request）
* B ping A 後，B 的鄰居資訊也被上報，此時雙向的 neigh_suppress 都有足夠資訊代答，A↔B 互通
* 測試步驟：
    1. 啟動所有節點，等待路由收斂
    2. 從 leaf-A ping leaf-B，預期初次可能不通（取決於鄰居表是否已同步）
    3. 從 leaf-B ping leaf-A
    4. 再次從 leaf-A ping leaf-B，預期此時互通

##### 3. 單一 Controller 斷線與恢復
* 測試步驟：
    1. 正常運行，確認所有 leaf 互通
    2. 關閉 Controller-10，Client 應 fallback 到 Controller-4（權威切換）
    3. 確認所有 leaf 仍互通
    4. 恢復 Controller-10，等待其重新握手、同步狀態
    5. 確認所有 leaf 仍互通
    6. 關閉 Controller-4，Client 應切換回 Controller-10
    7. 確認所有 leaf 仍互通
    8. 恢復 Controller-4，確認恢復正常

##### 4. 途經轉發節點斷線（topology_update 驗證）
* 前置：透過 tc 設定延遲，使部分路徑的最短路必須經過中繼 Client（例如 1→3→5，其中 3 是轉發節點）
* 測試步驟：
    1. 正常運行，確認 leaf-1 可 ping leaf-5（路徑經過 Client-3 轉發）
    2. 關閉 Client-3
    3. Controller 偵測到 Client-3 離線，等待 topology_update_debounce 後重新計算 RouteMatrix
    4. 確認 topology_update 產生新路由，leaf-1 仍可 ping leaf-5（改走其他路徑）
    5. 恢復 Client-3，確認 Client-3 能重新握手、重建 session
    6. 等待 sync_new_client_debounce 後觸發新一輪 Probe，RouteMatrix 更新
    7. 確認所有 leaf 恢復互通，且路由可能恢復經過 Client-3 轉發（若仍為最短路）

##### 5. Broadcast / Multicast 轉發測試
* 測試步驟：
    1. 從 leaf-A 發送 broadcast（例如 arping -b），確認所有其他 leaf 收到
    2. 確認 broadcast 封包未經過 vxlan data plane（vxlan device 上無 broadcast FDB entry）
    3. 確認 Controller relay 的 broadcast 不會回送給來源 Client

##### 6. 雙棧路由測試
* 驗證 v4-only（1,2）↔ 雙棧（3,4）↔ v6-only（5,6）的路由正確性
* 測試步驟：
    1. leaf-1（v4-only）ping leaf-5（v6-only），確認經由雙棧節點轉發成功
    2. 確認 FDB 寫入正確的 vxlan device（v4 段寫 vxlan-v4，v6 段寫 vxlan-v6）

#### 7. IP 變動測試
* 驗證 IP 變動，可以順利
    1. 新的 local bind ip 同步到 vxlan 介面
    2. 使用新的 local IP 進行 tcp udp 通訊
    3. 控制器能更新 client ip 變化，推送給其他節點
    4. 其他節點能更新 state 和同步到 kernel

所以要驗證 1, 3, 5 連線成功後，介面卡移除舊 IP ，新增 100+ id 的 IP ，然後呼叫 API 更新
