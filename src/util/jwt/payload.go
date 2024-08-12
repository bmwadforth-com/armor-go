package jwt

import (
	"encoding/base64"
	"encoding/json"
)

func (p *Payload) toJson() ([]byte, error) {
	jsonBytes, err := json.Marshal(p.ClaimSet)
	if err != nil {
		return nil, err
	}

	return jsonBytes, nil
}

func (p *Payload) toBase64() ([]byte, error) {
	jsonBytes, err := p.toJson()
	if err != nil {
		return nil, err
	}

	b64Bytes := base64.RawURLEncoding.EncodeToString(jsonBytes)

	p.raw = []byte(b64Bytes)

	return []byte(b64Bytes), nil
}

func (p *Payload) fromJson(b []byte) (*Payload, error) {
	err := json.Unmarshal(b, &p.ClaimSet)
	if err != nil {
		return nil, err
	}

	return p, nil
}

func (p *Payload) fromBase64(b []byte) (*Payload, error) {
	jsonBytes, err := base64.RawURLEncoding.DecodeString(string(b))
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(jsonBytes, &p.ClaimSet)
	if err != nil {
		return nil, err
	}

	return p, nil
}
