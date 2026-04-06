package vlog

import (
	"log"
	"sync/atomic"
)

// Log levels
const (
	LevelError   = 0
	LevelWarn    = 1
	LevelInfo    = 2
	LevelDebug   = 3
	LevelVerbose = 4
)

var level int32 = LevelInfo

func SetLevel(l int)  { atomic.StoreInt32(&level, int32(l)) }
func GetLevel() int   { return int(atomic.LoadInt32(&level)) }

func Errorf(format string, args ...any)   { log.Printf(format, args...) }
func Warnf(format string, args ...any)    { if GetLevel() >= LevelWarn { log.Printf(format, args...) } }
func Infof(format string, args ...any)    { if GetLevel() >= LevelInfo { log.Printf(format, args...) } }
func Debugf(format string, args ...any)   { if GetLevel() >= LevelDebug { log.Printf(format, args...) } }
func Verbosef(format string, args ...any) { if GetLevel() >= LevelVerbose { log.Printf(format, args...) } }

// Fatalf logs and exits (always shown).
func Fatalf(format string, args ...any) { log.Fatalf(format, args...) }

// ParseLevel converts a string to a log level.
func ParseLevel(s string) int {
	switch s {
	case "error":
		return LevelError
	case "warn":
		return LevelWarn
	case "info":
		return LevelInfo
	case "debug":
		return LevelDebug
	case "verbose":
		return LevelVerbose
	default:
		return LevelInfo
	}
}
