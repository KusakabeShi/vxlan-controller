package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"vxlan-controller/pkg/config"
	"vxlan-controller/pkg/controller"
	"vxlan-controller/pkg/vlog"
)

func main() {
	configPath := flag.String("config", "controller.yaml", "path to controller config file")
	defaultConfig := flag.Bool("default-config", false, "print default config and exit")
	logLevel := flag.String("log-level", "", "log level: error, warn, info, debug, verbose (overrides config)")
	flag.Parse()

	if *defaultConfig {
		data, err := config.DefaultControllerConfigYAML()
		if err != nil {
			log.Fatalf("Failed to marshal default config: %v", err)
		}
		fmt.Print(string(data))
		return
	}

	cfg, err := config.LoadControllerConfig(*configPath)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// Set log level: CLI flag overrides config
	if *logLevel != "" {
		vlog.SetLevel(vlog.ParseLevel(*logLevel))
	} else if cfg.LogLevel != "" {
		vlog.SetLevel(vlog.ParseLevel(cfg.LogLevel))
	}

	ctrl := controller.New(cfg)

	// Signal handler
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)

	go func() {
		<-sigCh
		log.Println("[Controller] shutting down...")
		ctrl.Stop()
	}()

	if err := ctrl.Run(); err != nil {
		log.Fatalf("Controller error: %v", err)
	}
}
