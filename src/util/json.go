package util

import (
	"encoding/json"
)

func SerializeJson(data interface{}) (string, error) {
	bytes, err := json.Marshal(data)
	if err != nil {
		SLogger.Errorf("failed to serialise json: %v", err)
		return "", err
	}

	return string(bytes), nil
}

func DeserializeJson[T any](data []byte) (T, error) {
	var response T
	err := json.Unmarshal(data, &response)
	if err != nil {
		SLogger.Errorf("failed to serialise json: %v", err)
		return response, err
	}

	return response, nil
}
