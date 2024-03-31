package util

import (
	"go.uber.org/zap"
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
