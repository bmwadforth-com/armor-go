package util_test

import (
	"fmt"
	"github.com/bmwadforth-com/armor-go/src/util"
	"github.com/stretchr/testify/assert"
	"os"
	"testing"
)

type TestConfig struct {
	Field1 string `json:"field1" env:"TEST_FIELD1"`
	Field2 int    `json:"field2" env:"TEST_FIELD2"`
}

func (c *TestConfig) Validate() error {
	if c.Field1 == "" {
		return fmt.Errorf("field1 is required")
	}
	if c.Field2 <= 0 {
		return fmt.Errorf("field2 must be positive")
	}
	return nil
}

func TestLoadConfiguration(t *testing.T) {
	configFileContent := []byte(`{"field1": "value1", "field2": 123}`)
	tempFile, err := os.CreateTemp("", "test_config.json")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tempFile.Name())

	if _, err := tempFile.Write(configFileContent); err != nil {
		t.Fatal(err)
	}

	var config TestConfig
	err = util.LoadConfiguration(tempFile.Name(), &config)
	assert.NoError(t, err)
	assert.Equal(t, "value1", config.Field1)
	assert.Equal(t, 123, config.Field2)

	configFileContent = []byte(`{"field1": "", "field2": -1}`)
	if _, err := tempFile.WriteAt(configFileContent, 0); err != nil {
		t.Fatal(err)
	}
	err = util.LoadConfiguration(tempFile.Name(), &config)
	assert.Error(t, err)
}

func TestLoadEnvironmentVariables(t *testing.T) {
	os.Setenv("TEST_FIELD1", "env_value1")
	os.Setenv("TEST_FIELD2", "456")
	defer os.Unsetenv("TEST_FIELD1")
	defer os.Unsetenv("TEST_FIELD2")

	var config TestConfig
	err := util.LoadEnvironmentVariables(&config)
	assert.NoError(t, err)
	assert.Equal(t, "env_value1", config.Field1)
	assert.Equal(t, 456, config.Field2)
}
