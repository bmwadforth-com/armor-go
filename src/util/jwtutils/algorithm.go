package jwt

import (
	"encoding/base64"
	"encoding/json"
	"errors"
)

var (
	jwsAlgorithms    = []AlgorithmType{HS256, RS256, None}
	jwsAlgorithmsMap = map[AlgorithmType]bool{
		HS256: true,
		RS256: true,
		None:  true,
	}

	jweAlgorithms    = []AlgorithmType{RSA_OAEP}
	jweAlgorithmsMap = map[AlgorithmType]bool{
		RSA_OAEP: true,
	}
)

func getTokenType(alg AlgorithmType) (TokenType, error) {
	if jwsAlgorithmsMap[alg] {
		return JWS, nil
	}

	if jweAlgorithmsMap[alg] {
		return JWE, nil
	}

	return "", errors.New("unable to determine token type - check algorithm is supported")
}

func getAlgType(tokenType TokenType, headerPart string) (AlgorithmType, error) {
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
