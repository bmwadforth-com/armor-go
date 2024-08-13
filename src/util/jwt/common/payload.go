package common

import (
	"encoding/base64"
	"encoding/json"
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
	jsonBytes, err := base64.RawURLEncoding.DecodeString(string(b))
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(jsonBytes, &p.Data)
	if err != nil {
		return nil, err
	}

	p.Metadata = &Metadata{
		Bytes:  b,
		Base64: string(b),
		Json:   string(jsonBytes),
	}

	return p, nil
}
