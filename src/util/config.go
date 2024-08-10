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

// LoadConfiguration loads configuration data from a JSON file into the provided
// 'config' struct. The 'config' struct should implement the 'Configuration'
// interface. If a 'Validate' method is present on the 'config' struct, it will
// be called after loading to ensure configuration validity.
//
// Returns an error if there's an issue reading the file, unmarshalling the JSON,
// or if validation fails.
func LoadConfiguration[T Configuration](configFilePath string, config T) error {
	bytes, err := os.ReadFile(configFilePath)
	if err != nil {
		return fmt.Errorf("failed to read config file: %w", err)
	}

	err = json.Unmarshal(bytes, &config)
	if err != nil {
		return fmt.Errorf("failed to unmarshal config: %w", err)
	}

	if v, ok := any(config).(interface{ Validate() error }); ok {
		if err := v.Validate(); err != nil {
			return fmt.Errorf("config validation failed: %w", err)
		}
	}

	return nil
}

// LoadEnvironmentVariables loads configuration data from environment variables
// into the provided 'config' struct. The 'config' struct should implement the
// 'Configuration' interface.  struct tags with the "env" key are used to map
// environment variables to struct fields. If a 'Validate' method is present on
// the 'config' struct, it will be called after loading to ensure configuration
// validity.
//
// Returns an error if there's an issue processing environment variables or if
// validation fails.
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
