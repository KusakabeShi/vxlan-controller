package client

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"

	"go.uber.org/zap"

	"vxlan-controller/pkg/types"
)

type bindAddrReq struct {
	BindAddr string `json:"bind_addr"`
}

type bindAddrResp struct {
	AF       string `json:"af"`
	BindAddr string `json:"bind_addr"`
}

func (c *Client) apiServerLoop(ctx context.Context) {
	if c.cfg.APIUnixSocket == "" {
		return
	}
	log := c.log.Named("api")
	sock := c.cfg.APIUnixSocket
	_ = os.Remove(sock)
	if err := os.MkdirAll(filepath.Dir(sock), 0o755); err != nil {
		log.Warn("mkdir api dir failed", zap.Error(err))
		return
	}
	ln, err := net.Listen("unix", sock)
	if err != nil {
		log.Warn("listen unix failed", zap.Error(err))
		return
	}
	defer ln.Close()

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/af/", func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimPrefix(r.URL.Path, "/v1/af/")
		parts := strings.Split(strings.Trim(path, "/"), "/")
		if len(parts) == 0 || parts[0] == "" {
			http.NotFound(w, r)
			return
		}
		af := parts[0]

		if len(parts) == 1 && r.Method == http.MethodGet {
			c.mu.Lock()
			afCfg := c.cfg.AFSettings[types.AFName(af)]
			c.mu.Unlock()
			if afCfg == nil {
				http.Error(w, "unknown af", http.StatusNotFound)
				return
			}
			_ = json.NewEncoder(w).Encode(bindAddrResp{AF: af, BindAddr: afCfg.BindAddr.Addr.String()})
			return
		}
		if len(parts) == 2 && parts[1] == "bind_addr" && r.Method == http.MethodPut {
			var req bindAddrReq
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, "bad json", http.StatusBadRequest)
				return
			}
			ip, err := netip.ParseAddr(req.BindAddr)
			if err != nil {
				http.Error(w, "bad bind_addr", http.StatusBadRequest)
				return
			}
			if err := c.UpdateBindAddr(types.AFName(af), ip); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			_ = json.NewEncoder(w).Encode(bindAddrResp{AF: af, BindAddr: ip.String()})
			return
		}
		http.NotFound(w, r)
	})

	srv := &http.Server{Handler: mux}
	go func() {
		<-ctx.Done()
		_ = srv.Close()
	}()
	if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Warn("api server exited", zap.Error(err))
	}
}
