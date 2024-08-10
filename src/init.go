package armor

import (
	"context"
	"github.com/bmwadforth-com/armor-go/src/util"
	"go.uber.org/zap"
	"os"
)

var (
	ArmorContext context.Context
	IsRelease    bool
	InitCalled   bool

	CleanupLogger func(*zap.Logger)
)

func InitArmor[T util.Configuration](isRelease bool, config T, configPath string) error {
	ArmorContext = context.Background()
	IsRelease = isRelease
	InitCalled = true
	CleanupLogger = util.InitLogger()

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
