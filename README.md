# vxlan-controller

VXLAN overlay controller + client (Go)。

此專案提供：
- **Controller**：收集 Client 上報的本地 MAC/IP（`RouteUpdateBatch`）、收集 probe latency/loss（`ProbeResults`），計算 `RouteMatrix`（Floyd-Warshall + `additional_cost` 權重），並用 `ControllerState`/`ControllerStateUpdate`（full-replace）推送給所有 Client。
- **Client**：建立 `bridge`/`vxlan`/`tap-inject`，上報本地路由、執行 probe，並根據 Controller 推送結果用 `bridge fdb replace/del` 寫入 unicast FDB。broadcast/multicast 由 Controller UDP relay 處理（不寫入 FDB）。

完整設計與架構細節請見 `DESIGN.md`、`ARCHITECTURE.md`。

## Key 產生（完全照 WireGuard）

本專案 private/public key 直接使用 WireGuard 的格式（base64 的 X25519 key）：

```bash
priv="$(wg genkey)"
pub="$(printf '%s' "$priv" | wg pubkey)"
echo "private_key: $priv"
echo "public_key:  $pub"
```

## Build

需求：Go 1.26+。

```bash
go build -o controller ./cmd/controller
go build -o client ./cmd/client
```

## Run

Controller：
```bash
./controller --config controller.yaml --log-level info
```

Client：
```bash
./client --config client.yaml --log-level info
```

YAML 欄位與預設值請以 `DESIGN.md` 為準（包含 `broadcast_pps_limit`、`ntp_resync_interval`、probe 的 `batch_id/seq/probe_id` 規則等）。

## Client API（Unix socket, REST + JSON）

在 Client YAML 設定 `api_unix_socket` 後會啟動 API server。

- `GET /v1/af/{af}`：查詢 bind_addr
- `PUT /v1/af/{af}/bind_addr`：更新 bind_addr（同時重建 sockets、更新 vxlan local、觸發重連）

範例：
```bash
curl --unix-socket /tmp/vxlan-controller.sock -sS http://localhost/v1/af/v4
curl --unix-socket /tmp/vxlan-controller.sock -sS -X PUT \
  http://localhost/v1/af/v4/bind_addr -d '{"bind_addr":"192.0.2.123"}'
```

## Tests

整合測試會使用 network namespace、vxlan、tc netem、tcpdump、以及 `wg` 產生 key，因此需要 root 權限與對應工具。

```bash
sudo bash tests/test_all.sh
```

