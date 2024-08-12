package jwt

import (
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

/*
func getAlgType(t *Token) (AlgorithmType, error) {
	if t == nil {
		return "", errors.New("token is nil")
	}

	if t.Raw == nil {
		return "", errors.New("token is empty")
	}

	err := t.Decode()
	if err != nil {
		return "", err
	}

	var algorithm AlgorithmType

	switch t.TokenType {
	case JWS:
		token, ok := t.tokenInstance.(*JwsToken)
		algorithm, ok = token.Header.Properties["alg"].(AlgorithmType)
		if !ok {
			algorithmStr, ok := token.Header.Properties["alg"].(string)
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
}*/
