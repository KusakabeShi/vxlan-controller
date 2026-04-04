package main

import (
	"context"
	"flag"
	"os"
	"os/signal"
	"syscall"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"vxlan-controller/pkg/client"
	"vxlan-controller/pkg/config"
)

func main() {
	var configPath string
	var logLevel string
	flag.StringVar(&configPath, "config", "", "client config yaml")
	flag.StringVar(&logLevel, "log-level", "info", "debug|info|warn|error")
	flag.Parse()

	if configPath == "" {
		_, _ = os.Stderr.WriteString("missing --config\n")
		os.Exit(2)
	}

	level := zapcore.InfoLevel
	_ = level.Set(logLevel)
	cfg := zap.NewProductionConfig()
	cfg.Level = zap.NewAtomicLevelAt(level)
	logger, _ := cfg.Build()
	defer logger.Sync()

	conf, err := config.LoadClientConfig(configPath)
	if err != nil {
		logger.Fatal("load config failed", zap.Error(err))
	}

	cl, err := client.New(conf, logger.Named("client"))
	if err != nil {
		logger.Fatal("init client failed", zap.Error(err))
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		<-sig
		cancel()
	}()

	if err := cl.Run(ctx); err != nil && err != context.Canceled {
		logger.Fatal("client exited", zap.Error(err))
	}
}

