package util

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/sethvargo/go-envconfig"
	"os"
)

type Configurable interface {
	Validate() error // Optional: Add a validation method if needed
}

/*
	How to use in Go project:
	var config struct {
		ProjectId          string `json:"ProjectId" env:"WEB_TEMPLATE__PROJECTID"`
		ApiKey             string `json:"ApiKey" env:"WEB_TEMPLATE__APIKEY"`
		JwtSigningKey      string `json:"jwtSigningKey" env:"WEB_TEMPLATE__JWTSIGNINGKEY"`
		FireStoreDatabase  string `json:"fireStoreDatabase" env:"WEB_TEMPLATE__FIRESTOREDATABASE"`
		CloudStorageBucket string `json:"cloudStorageBucket" env:"WEB_TEMPLATE__CLOUDSTORAGEBUCKET"`
		Database           struct {
			Host     string `json:"host" env:"WEB_TEMPLATE__DATABASE_HOST"`
			Name     string `json:"name" env:"WEB_TEMPLATE__DATABASE_NAME"`
			Username string `json:"user" env:"WEB_TEMPLATE__DATABASE_USERNAME"`
			Password string `json:"pass" env:"WEB_TEMPLATE__DATABASE_PASSWORD"`
			Port     string `json:"port" env:"WEB_TEMPLATE__DATABASE_PORT"`
			SSL      bool   `json:"SSL" env:"WEB_TEMPLATE__DATABASE_SSL"`
		} `json:"database"`
	}

	err := util.LoadConfiguration("path/to/config.json", &config)
	if err != nil {
		// Handle error
	}

    // config.ProjectId will now have the value loaded from the JSON file

	err = util.LoadEnvironmentVariables(&config)
	if err != nil {
		// Handle error
	}

	// config.ProjectId will now have the value loaded from the 'WEB_TEMPLATE__PROJECTID' env variable
*/

func LoadConfiguration[T Configurable](configFilePath string, config T) error {
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

func LoadEnvironmentVariables[T Configurable](config T) error {
	ctx := context.Background()

	if err := envconfig.Process(ctx, &config); err != nil {
		return fmt.Errorf("failed to process environment variables: %w", err)
	}

	if v, ok := any(config).(interface{ Validate() error }); ok {
		if err := v.Validate(); err != nil {
			return fmt.Errorf("config validation failed: %w", err)
		}
	}

	return nil
}
