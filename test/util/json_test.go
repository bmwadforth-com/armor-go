package util_test

import (
	"github.com/bmwadforth/armor-go/src/util"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestSerializeJson_Success(t *testing.T) {
	data := struct {
		Name string `json:"name"`
		Age  int    `json:"age"`
	}{Name: "John", Age: 30}

	result, err := util.SerializeJson(data)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	assert.Containsf(t, result, "John", "John is in the serialized string")
}

func TestSerializeJson_Error(t *testing.T) {
	_, err := util.SerializeJson(make(chan int))
	if err == nil {
		t.Error("Expected error, but got nil")
	}

	assert.Error(t, err, "Unable to serialize channels")
}

func TestDeserializeJson_Success(t *testing.T) {
	jsonData := []byte(`{"name": "Bob", "age": 25}`)
	type Person struct {
		Name string `json:"name"`
		Age  int    `json:"age"`
	}

	var result Person
	result, err := util.DeserializeJson[Person](jsonData)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	assert.Equalf(t, "Bob", result.Name, "Bob exists in deserialized struct")
	assert.Equalf(t, 25, result.Age, "Bobs age of 25 exists in deserialized struct")
}
