package util

import (
	"fmt"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"log"
	"os"
)

var (
	SLogger *zap.SugaredLogger
	Logger  *zap.Logger
)

func InitLogger(isRelease bool, minimumLevel zapcore.Level) func() {
	if isRelease {
		encoderConfig := zap.NewProductionEncoderConfig()
		encoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder

		core := zapcore.NewCore(
			zapcore.NewJSONEncoder(encoderConfig),
			zapcore.AddSync(os.Stdout),
			zap.NewAtomicLevelAt(minimumLevel),
		)

		Logger = zap.New(core)
		SLogger = Logger.Sugar()
	} else {
		encoderConfig := zap.NewDevelopmentEncoderConfig()
		encoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder
		encoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder

		core := zapcore.NewCore(
			zapcore.NewConsoleEncoder(encoderConfig),
			zapcore.AddSync(os.Stdout),
			zap.NewAtomicLevelAt(minimumLevel),
		)

		Logger = zap.New(core)
		SLogger = Logger.Sugar()
	}

	return func() {
		err := Logger.Sync()
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

func LogFatal(template string, args ...interface{}) {
	msg := fmt.Sprintf(template, args...)
	SLogger.Logf(zap.FatalLevel, fmt.Sprintf("[Armor - FATAL]: %s", msg))
}
