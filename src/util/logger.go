package util

import (
	"fmt"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"log"
)

var (
	SLogger *zap.SugaredLogger
	Logger  *zap.Logger
)

func InitLogger() func(*zap.Logger) {
	Logger, _ = zap.NewProduction()
	SLogger = Logger.Sugar()

	return func(logger *zap.Logger) {
		err := logger.Sync()
		if err != nil {
			log.Fatalf("failed to flush log buffer: %v", err)
		}
	}
}

func Log(lvl zapcore.Level, template string, args ...interface{}) {
	msg := fmt.Sprintf(template, args...)
	SLogger.Logf(lvl, fmt.Sprintf("[Armor]: %s", msg))
}

func LogInfo(template string, args ...interface{}) {
	msg := fmt.Sprintf(template, args...)
	SLogger.Logf(zap.InfoLevel, fmt.Sprintf("[Armor - INFO]: %s", msg))
}

func LogWarn(template string, args ...interface{}) {
	msg := fmt.Sprintf(template, args...)
	SLogger.Logf(zap.WarnLevel, fmt.Sprintf("[Armor - WARN]: %s", msg))
}

func LogError(template string, args ...interface{}) {
	msg := fmt.Sprintf(template, args...)
	SLogger.Logf(zap.ErrorLevel, fmt.Sprintf("[Armor - ERROR]: %s", msg))
}
