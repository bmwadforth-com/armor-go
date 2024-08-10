package util

import (
	"encoding/json"
	"errors"
	"reflect"
)

func SerializeJson(data interface{}) (string, error) {
	if !isSerializable(data) {
		return "", errors.New("unsupported data type for JSON serialization")
	}

	bytes, err := json.Marshal(data)
	if err != nil {
		LogError("failed to serialize json: %v", err)
		return "", err
	}

	return string(bytes), nil
}

func DeserializeJson[T any](data []byte) (T, error) {
	var response T
	err := json.Unmarshal(data, &response)
	if err != nil {
		LogError("failed to deserialized json: %v", err)
		return response, err
	}

	return response, nil
}

// isSerializable checks if a given value can be serialized to JSON.
func isSerializable(value interface{}) bool {
	kind := reflect.TypeOf(value).Kind()

	switch kind {
	case reflect.Chan, reflect.Func, reflect.UnsafePointer:
		return false
	}

	if kind == reflect.Struct {
		v := reflect.ValueOf(value)
		for i := 0; i < v.NumField(); i++ {
			if !isSerializable(v.Field(i).Interface()) {
				return false
			}
		}
	}

	return true
}
