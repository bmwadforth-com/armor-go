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

// InitLogger initializes a global logger based on the provided configuration.
//
// Parameters:
//   - isRelease: If true, it sets up a production-ready JSON logger formatted for Cloud Run.
//     If false, it uses a development-friendly console logger with color-coded levels.
//   - minimumLevel: Sets the minimum log level to be captured. Logs below this level will be ignored.
//
// Returns:
//   - A function that can be called to flush any remaining log messages before the program terminates.
//
// This function sets up the global `Logger` and `SLogger` variables, which can then be used throughout the application for logging.
// The logger's behavior and output format are determined by the `isRelease` flag.
// In release mode, logs are structured in JSON format, suitable for Cloud Run's logging infrastructure.
// In development mode, logs are output to the console with color-coded levels for easier readability.
func InitLogger(isRelease bool, minimumLevel zapcore.Level) func() {
	var core zapcore.Core

	if isRelease {
		var encoderConfig = zapcore.EncoderConfig{
			TimeKey:        "time",
			LevelKey:       "severity",
			NameKey:        "logger",
			CallerKey:      "caller",
			MessageKey:     "message",
			StacktraceKey:  "stacktrace",
			LineEnding:     zapcore.DefaultLineEnding,
			EncodeTime:     zapcore.ISO8601TimeEncoder,
			EncodeDuration: zapcore.MillisDurationEncoder,
			EncodeCaller:   zapcore.ShortCallerEncoder,
		}

		// Map Zap levels to Cloud Run severity levels
		encoderConfig.EncodeLevel = func(l zapcore.Level, enc zapcore.PrimitiveArrayEncoder) {
			switch l {
			case zapcore.DebugLevel:
				enc.AppendString("DEBUG")
			case zapcore.InfoLevel:
				enc.AppendString("INFO")
			case zapcore.WarnLevel:
				enc.AppendString("WARNING")
			case zapcore.ErrorLevel, zapcore.DPanicLevel, zapcore.PanicLevel, zapcore.FatalLevel:
				enc.AppendString("ERROR")
			default:
				enc.AppendString("UNKNOWN")
			}
		}

		core = zapcore.NewCore(
			zapcore.NewJSONEncoder(encoderConfig),
			zapcore.AddSync(os.Stdout),
			zap.NewAtomicLevelAt(minimumLevel),
		)
	} else {
		encoderConfig := zap.NewDevelopmentEncoderConfig()
		encoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder
		encoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder

		core = zapcore.NewCore(
			zapcore.NewConsoleEncoder(encoderConfig),
			zapcore.AddSync(os.Stdout),
			zap.NewAtomicLevelAt(minimumLevel),
		)
	}

	Logger = zap.New(core)
	SLogger = Logger.Sugar()

	return func() {
		err := Logger.Sync()
		if err != nil {
			log.Fatalf("failed to flush log buffer: %v", err)
		}
	}
}

func Log(lvl zapcore.Level, template string, args ...interface{}) {
	if SLogger == nil {
		panic("[ARMOR] Before calling Log you must call InitArmor")
	}
	msg := fmt.Sprintf(template, args...)
	SLogger.Logf(lvl, fmt.Sprintf("[ARMOR]: %s", msg))
}

func LogInfo(template string, args ...interface{}) {
	if SLogger == nil {
		panic("[ARMOR] Before calling LogInfo you must call InitArmor")
	}
	msg := fmt.Sprintf(template, args...)
	SLogger.Logf(zap.InfoLevel, fmt.Sprintf("[ARMOR]: %s", msg))
}

func LogWarn(template string, args ...interface{}) {
	if SLogger == nil {
		panic("[ARMOR] Before calling LogWarn you must call InitArmor")
	}
	msg := fmt.Sprintf(template, args...)
	SLogger.Logf(zap.WarnLevel, fmt.Sprintf("[ARMOR]: %s", msg))
}

func LogError(template string, args ...interface{}) {
	if SLogger == nil {
		panic("[ARMOR] Before calling LogError you must call InitArmor")
	}
	msg := fmt.Sprintf(template, args...)
	SLogger.Logf(zap.ErrorLevel, fmt.Sprintf("[ARMOR]: %s", msg))
}

func LogFatal(template string, args ...interface{}) {
	if SLogger == nil {
		panic("[ARMOR] Before calling LogFetal you must call InitArmor")
	}
	msg := fmt.Sprintf(template, args...)
	SLogger.Logf(zap.FatalLevel, fmt.Sprintf("[ARMOR]: %s", msg))
}
