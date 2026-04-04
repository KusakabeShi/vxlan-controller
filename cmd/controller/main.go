package main

import (
	"context"
	"flag"
	"os"
	"os/signal"
	"syscall"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"vxlan-controller/pkg/config"
	"vxlan-controller/pkg/controller"
)

func main() {
	var configPath string
	var logLevel string
	flag.StringVar(&configPath, "config", "", "controller config yaml")
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

	conf, err := config.LoadControllerConfig(configPath)
	if err != nil {
		logger.Fatal("load config failed", zap.Error(err))
	}

	ctrl, err := controller.New(conf, logger.Named("controller"))
	if err != nil {
		logger.Fatal("init controller failed", zap.Error(err))
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		<-sig
		cancel()
	}()

	if err := ctrl.Run(ctx); err != nil && err != context.Canceled {
		logger.Fatal("controller exited", zap.Error(err))
	}
}

