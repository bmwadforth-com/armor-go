package common

import (
	"encoding/base64"
	"encoding/json"
	"errors"
)

func (h *Header) Serialize() ([]byte, error) {
	jsonBytes, err := json.Marshal(h.Data)
	if err != nil {
		return nil, err
	}

	b64Bytes := base64.RawURLEncoding.EncodeToString(jsonBytes)

	h.Metadata = &Metadata{
		Bytes:  jsonBytes,
		Base64: b64Bytes,
		Json:   string(jsonBytes),
	}

	return []byte(b64Bytes), nil
}

func (h *Header) Deserialize(b []byte) (*Header, error) {
	jsonBytes, err := base64.RawURLEncoding.DecodeString(string(b))
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(jsonBytes, &h.Data)
	if err != nil {
		return nil, err
	}

	h.Metadata = &Metadata{
		Bytes:  b,
		Base64: string(b),
		Json:   string(jsonBytes),
	}

	return h, nil
}

func (h *Header) GetAlgorithm() (AlgorithmType, error) {
	if h.Metadata == nil {
		return "", errors.New("arguments were invalid")
	}

	jsonBytes := h.Metadata.Json

	var headerMap map[string]interface{}
	if err := json.Unmarshal([]byte(jsonBytes), &headerMap); err != nil {
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

func (h *Header) GetEncryptionAlgorithm() (AuthAlgorithmType, error) {
	if h.Metadata == nil {
		return "", errors.New("arguments were invalid")
	}

	jsonBytes := h.Metadata.Json

	var headerMap map[string]interface{}
	if err := json.Unmarshal([]byte(jsonBytes), &headerMap); err != nil {
		return "", err
	}

	algorithm, ok := headerMap["enc"].(AuthAlgorithmType)
	if !ok {
		algorithmStr, ok := headerMap["enc"].(string)
		if ok {
			algorithm = AuthAlgorithmType(algorithmStr)
		} else {
			return "", errors.New("algorithm could not be decoded")
		}
	}

	return algorithm, nil
}
