package jwt

import (
	"errors"
	"strings"
)

type TokenType string

const (
	JWS TokenType = "jws"
	JWE TokenType = "jwe"
)

type AlgorithmType string

const (
	// JWS
	HS256 AlgorithmType = "HS256"
	RS256 AlgorithmType = "RS256"
	None  AlgorithmType = "none"

	// JWE
	RSA_OAEP AlgorithmType = "RSA-OAEP"
)

type tokenInstance interface {
	encode() ([]byte, error)
	decode(parts []string) error
	validate() (bool, error)
}

type Token struct {
	TokenType
	tokenInstance
	Claims ClaimSet
	Raw    []byte
}

func New(alg AlgorithmType, claims ClaimSet, key []byte) (*Token, error) {
	var tokenType TokenType
	if jwsAlgorithmsMap[alg] {
		tokenType = JWS
	} else if jweAlgorithmsMap[alg] {
		tokenType = JWE
	}

	if tokenType == "" {
		return nil, errors.New("invalid algorithm")
	}

	token := new(Token)
	token.TokenType = tokenType
	token.Raw = []byte{}
	token.Claims = claims

	switch token.TokenType {
	case JWS:
		jwsToken, err := newJwsToken(alg, claims, key)
		if err != nil {
			return nil, err
		}
		token.tokenInstance = jwsToken
		token.Claims = claims
		break
	case JWE:
		jweToken, err := newJweToken(alg, claims, key)
		if err != nil {
			return nil, err
		}
		token.tokenInstance = jweToken
		token.Claims = claims
		break
	}

	return token, nil
}

func Encode(t *Token) ([]byte, error) {
	if t.Raw == nil || t.TokenType == "" {
		return nil, errors.New("invalid token. make sure you call New before you call Encode")
	}

	var err error
	switch t.TokenType {
	case JWS:
		tokenInstance, ok := t.tokenInstance.(*JwsToken)
		if !ok {
			return nil, errors.New("invalid token")
		}
		t.Raw, err = tokenInstance.encode()
	case JWE:
		tokenInstance, ok := t.tokenInstance.(*JweToken)
		if !ok {
			return nil, errors.New("invalid token")
		}
		t.Raw, err = tokenInstance.encode()
	}

	if err != nil {
		return nil, err
	}

	return t.Raw, nil
}

func Decode(tokenString string, key []byte) (*Token, error) {
	token := Token{Raw: []byte(tokenString)}
	jwtParts := strings.Split(tokenString, ".")

	switch len(jwtParts) {
	case 3:
		token.TokenType = JWS
		tokenInstance, ok := token.tokenInstance.(*JwsToken)
		if !ok {
			return nil, errors.New("invalid token")
		}
		tokenInstance.key = key

		err := tokenInstance.decode(jwtParts)
		if err != nil {
			return nil, err
		}
	case 5:
		token.TokenType = JWE
		tokenInstance, ok := token.tokenInstance.(*JweToken)
		if !ok {
			return nil, errors.New("invalid token")
		}

		err := tokenInstance.decode(jwtParts)
		if err != nil {
			return nil, err
		}
	default:
		return nil, errors.New("invalid JWT format: unexpected number of parts")
	}

	return &token, nil
}

/*
func Validate(t *Token) (bool, error) {
	if t.Raw == nil {
		return false, errors.New("jwt token is empty - you must call parse before validate")
	}

	algorithm, err := getAlgType(t)
	if err != nil {
		return false, err
	}

	tokenType, err := getTokenType(algorithm)
	if err != nil {
		return false, err
	}

	switch tokenType {
	case JWS:
		return t.ValidateJws()
	case JWE:
		log.Fatal("JWE Not Implemented")
	}

	return false, errors.New("unable to decode - please check algorithm")
}
*/
