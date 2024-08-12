package common

import (
	"encoding/base64"
	"encoding/json"
	"errors"
)

func GetTokenType(alg AlgorithmType) (TokenType, error) {
	if JwsAlgorithmsMap[alg] {
		return JWS, nil
	}

	if JweAlgorithmsMap[alg] {
		return JWE, nil
	}

	return "", errors.New("unable to determine token type - check algorithm is supported")
}

func GetAlgType(tokenType TokenType, headerPart string) (AlgorithmType, error) {
	if headerPart == "" || tokenType == "" {
		return "", errors.New("arguments were invalid")
	}

	headerJSON, err := base64.RawURLEncoding.DecodeString(headerPart)
	if err != nil {
		return "", err
	}

	var headerMap map[string]interface{}
	if err := json.Unmarshal(headerJSON, &headerMap); err != nil {
		return "", err
	}

	var algorithm AlgorithmType
	var ok bool
	switch tokenType {
	case JWS:
		algorithm, ok = headerMap["alg"].(AlgorithmType)
		if !ok {
			algorithmStr, ok := headerMap["alg"].(string)
			if ok {
				algorithm = AlgorithmType(algorithmStr)
			} else {
				return "", errors.New("algorithm could not be decoded")
			}
		}
	case JWE:
		return "", errors.New("support for jwe tokens not implemented")
	}

	return algorithm, nil
}
