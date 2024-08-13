package armor

import (
	"context"
	"github.com/bmwadforth-com/armor-go/src/util"
	"go.uber.org/zap/zapcore"
)

var (
	ArmorContext  context.Context
	IsRelease     bool
	InitCalled    bool
	CleanupLogger func()
)

// InitArmor initializes the application's configuration and logging based on the release mode.
//
// Parameters:
//   - isRelease: Indicates whether the application is running in release mode (true) or not (false).
//   - minLevel: The minimum logging level to be used (e.g., zapcore.InfoLevel).
//   - config: A pointer to the configuration struct to be populated.
//   - configPath: The path to the configuration file (used in non-release mode). e.g. config.local.json
//
// Returns:
//   - An error if there's an issue loading configuration or environment variables.
func InitArmor[T util.Configuration](isRelease bool, minLevel zapcore.Level, config *T, configPath string) error {
	ArmorContext = context.Background()
	IsRelease = isRelease
	InitCalled = true

	CleanupLogger = util.InitLogger(isRelease, minLevel)

	if IsRelease {
		if err := util.LoadEnvironmentVariables(*config); err != nil {
			util.LogFatal("Error loading environment variables: %v", err)
			return err
		}
	} else {
		if err := util.LoadConfiguration(configPath, *config); err != nil {
			util.LogFatal("Error loading configuration file: %v", err)
			return err
		}
	}

	return nil
}
