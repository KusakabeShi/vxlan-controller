package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"vxlan-controller/pkg/client"
	"vxlan-controller/pkg/config"
	"vxlan-controller/pkg/vlog"
)

func main() {
	configPath := flag.String("config", "client.yaml", "path to client config file")
	defaultConfig := flag.Bool("default-config", false, "print default config and exit")
	logLevel := flag.String("log-level", "", "log level: error, warn, info, debug, verbose (overrides config)")
	flag.Parse()

	if *defaultConfig {
		data, err := config.DefaultClientConfigYAML()
		if err != nil {
			log.Fatalf("Failed to marshal default config: %v", err)
		}
		fmt.Print(string(data))
		return
	}

	cfg, err := config.LoadClientConfig(*configPath)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// Set log level: CLI flag overrides config
	if *logLevel != "" {
		vlog.SetLevel(vlog.ParseLevel(*logLevel))
	} else if cfg.LogLevel != "" {
		vlog.SetLevel(vlog.ParseLevel(cfg.LogLevel))
	}

	cl := client.New(cfg)

	// Signal handler
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)

	go func() {
		<-sigCh
		log.Println("[Client] shutting down...")
		cl.Stop()
	}()

	if err := cl.Run(); err != nil {
		log.Fatalf("Client error: %v", err)
	}
}
