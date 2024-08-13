package util

import (
	"encoding/json"
	"errors"
	"reflect"
)

// SerializeJson converts the provided data into a JSON-formatted string.
//
// Parameters:
//   - data: The data to be serialized. It must be of a type supported by the `json.Marshal` function.
//     The `isSerializable` function is used to check this beforehand.
//
// Returns:
//   - A string containing the JSON representation of the data.
//   - An error if the serialization process fails or if the data type is unsupported.
//
// This function first checks if the provided data is serializable using the `isSerializable` helper function.
// If it is, it uses `json.Marshal` to convert the data into a byte slice representing the JSON format.
// Any errors during marshaling are logged and returned.
// Finally, the byte slice is converted into a string and returned along with a nil error if the process was successful.
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

// DeserializeJson unmarshal the provided JSON data into a value of the specified generic type T.
//
// Parameters:
//   - data: A byte slice containing the JSON data to be deserialized.
//
// Returns:
//   - A value of type T, populated with the deserialized data.
//   - An error if the deserialization process fails.
//
// This function uses the `json.Unmarshal` function to convert the JSON data in the 'data' byte slice into a value of the specified generic type 'T'.
// If the unmarshalling process encounters an error, it logs the error using the `LogError` function and returns the error along with the zero value of type 'T'.
// If the unmarshalling is successful, it returns the deserialized value of type 'T' and a nil error.
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
