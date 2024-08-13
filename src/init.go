package armor

import (
	"context"
	"github.com/bmwadforth-com/armor-go/src/util"
	"go.uber.org/zap/zapcore"
	"os"
)

var (
	ArmorContext context.Context
	IsRelease    bool
	InitCalled   bool

	CleanupLogger func()
)

func InitArmor[T util.Configuration](isRelease bool, minLevel zapcore.Level, config T, configPath string) error {
	ArmorContext = context.Background()
	IsRelease = isRelease
	InitCalled = true
	CleanupLogger = util.InitLogger(isRelease, minLevel)

	if IsRelease || os.Getenv("APP_ENV") == "PRODUCTION" {
		err := util.LoadEnvironmentVariables(config)
		if err != nil {
			util.LogError("%v", err)
			return err
		}
	} else {
		err := util.LoadConfiguration(configPath, config)
		if err != nil {
			util.LogError("%v", err)
			return err
		}
	}

	return nil
}
