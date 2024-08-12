package common

import (
	"encoding/base64"
	"encoding/json"
	"errors"
)

func (h *Header) toJson() ([]byte, error) {
	jsonBytes, err := json.Marshal(h.Properties)
	if err != nil {
		return nil, err
	}

	return jsonBytes, nil
}

func (h *Header) ToBase64() ([]byte, error) {
	jsonBytes, err := h.toJson()
	if err != nil {
		return nil, err
	}

	b64Bytes := base64.RawURLEncoding.EncodeToString(jsonBytes)

	h.Raw = []byte(b64Bytes)

	return []byte(b64Bytes), nil
}

func (h *Header) fromJson(b []byte) (*Header, error) {
	err := json.Unmarshal(b, &h.Properties)
	if err != nil {
		return nil, err
	}

	return h, nil
}

func (h *Header) FromBase64(b []byte) (*Header, error) {
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

func (h *Header) GetAlgorithm() (AlgorithmType, error) {
	if h.Raw == nil {
		return "", errors.New("arguments were invalid")
	}

	headerJSON, err := base64.RawURLEncoding.DecodeString(string(h.Raw))
	if err != nil {
		return "", err
	}

	var headerMap map[string]interface{}
	if err := json.Unmarshal(headerJSON, &headerMap); err != nil {
		return "", err
	}

	algorithm, ok := headerMap["alg"].(AlgorithmType)
	if !ok {
		algorithmStr, ok := headerMap["alg"].(string)
		if ok {
			algorithm = AlgorithmType(algorithmStr)
		} else {
			return "", errors.New("algorithm could not be decoded")
		}
	}

	return algorithm, nil
}
