package jwt

import (
	"encoding/base64"
	"encoding/json"
)

func (h *Header) toJson() ([]byte, error) {
	jsonBytes, err := json.Marshal(h.Properties)
	if err != nil {
		return nil, err
	}

	return jsonBytes, nil
}

func (h *Header) toBase64() ([]byte, error) {
	jsonBytes, err := h.toJson()
	if err != nil {
		return nil, err
	}

	b64Bytes := base64.RawURLEncoding.EncodeToString(jsonBytes)

	h.raw = []byte(b64Bytes)

	return []byte(b64Bytes), nil
}

func (h *Header) fromJson(b []byte) (*Header, error) {
	err := json.Unmarshal(b, &h.Properties)
	if err != nil {
		return nil, err
	}

	return h, nil
}

func (h *Header) fromBase64(b []byte) (*Header, error) {
	jsonBytes, err := base64.RawURLEncoding.DecodeString(string(b))
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(jsonBytes, &h.Properties)
	if err != nil {
		return nil, err
	}

	return h, nil
}
