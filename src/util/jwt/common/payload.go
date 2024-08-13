package common

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
)

func (p *Payload) Serialize() ([]byte, error) {
	jsonBytes, err := json.Marshal(p.Data)
	if err != nil {
		return nil, err
	}

	b64Bytes := base64.RawURLEncoding.EncodeToString(jsonBytes)

	p.Metadata = &Metadata{
		Bytes:  jsonBytes,
		Base64: b64Bytes,
		Json:   string(jsonBytes),
	}

	return []byte(b64Bytes), nil
}

func (p *Payload) Deserialize(b []byte) (*Payload, error) {
	var jsonBytes []byte
	var err error

	if isBase64(b) {
		jsonBytes, err = base64.RawURLEncoding.DecodeString(string(b))
		if err != nil {
			return nil, fmt.Errorf("failed to decode Base64: %w", err)
		}
	} else {
		jsonBytes = b
	}

	err = json.Unmarshal(jsonBytes, &p.Data)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal JSON: %w", err)
	}

	p.Metadata = &Metadata{
		Bytes:  b,
		Base64: string(b),
		Json:   string(jsonBytes),
	}

	return p, nil
}

func isBase64(b []byte) bool {
	_, err := base64.RawURLEncoding.DecodeString(string(b))
	return err == nil
}
