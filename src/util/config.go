package util

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/sethvargo/go-envconfig"
	"os"
)

// Configuration represents a type that can be loaded with configuration data
// and optionally validated.
type Configuration interface {
	Validate() error
}

// LoadConfiguration loads and unmarshals configuration from a JSON file.
// It also performs validation on the configuration if the `Validate()` method is implemented.
//
// Parameters:
//   - configFilePath: The path to the JSON configuration file.
//   - config: A pointer to the configuration struct to be populated.
//
// Returns:
//   - An error if there's an issue reading the file, unmarshaling the JSON, or validating the configuration.
func LoadConfiguration[T Configuration](configFilePath string, config T) error {
	bytes, err := os.ReadFile(configFilePath)
	if err != nil {
		return fmt.Errorf("failed to read config file: %w", err)
	}

	err = json.Unmarshal(bytes, &config)
	if err != nil {
		return fmt.Errorf("failed to unmarshal config: %w", err)
	}

	// Check if the configuration type implements the Validate() method
	if v, ok := any(config).(interface{ Validate() error }); ok {
		// If it does, call the Validate() method for configuration validation
		if err := v.Validate(); err != nil {
			return fmt.Errorf("config validation failed: %w", err)
		}
	}

	return nil
}

// LoadEnvironmentVariables loads configuration values from environment variables into the provided configuration struct.
// It utilizes the `envconfig` package to process the environment variables and populate the configuration struct accordingly.
// Additionally, if the configuration struct implements the `Validate` method, it performs validation on the loaded configuration.
//
// Parameters:
//   - config: A pointer to the configuration struct to be populated with values from environment variables.
//
// Returns:
//   - An error if there's an issue processing environment variables or validating the configuration.
func LoadEnvironmentVariables[T Configuration](config T) error {
	ctx := context.Background()

	if err := envconfig.Process(ctx, config); err != nil {
		return fmt.Errorf("failed to process environment variables: %w", err)
	}

	if v, ok := any(config).(interface{ Validate() error }); ok {
		if err := v.Validate(); err != nil {
			return fmt.Errorf("config validation failed: %w", err)
		}
	}

	return nil
}
