package jwt

import (
	"errors"
	"github.com/bmwadforth-com/armor-go/src/util/jwt/common"
	"github.com/bmwadforth-com/armor-go/src/util/jwt/jwe"
	"github.com/bmwadforth-com/armor-go/src/util/jwt/jws"
	"log"
	"strings"
)

func New(alg common.AlgorithmSuite, claims common.ClaimSet, key []byte) (*common.Token, error) {
	var tokenType common.TokenType
	if common.JwsAlgorithmsMap[alg.AlgorithmType] {
		tokenType = common.JWS
	} else if common.JweAlgorithmsMap[alg.AlgorithmType] {
		tokenType = common.JWE
	}

	if tokenType == "" {
		return nil, errors.New("invalid algorithm")
	}

	token := new(common.Token)
	token.TokenType = tokenType
	token.Raw = []byte{}
	token.Claims = claims

	switch token.TokenType {
	case common.JWS:
		jwsToken, err := jws.New(alg.AlgorithmType, claims, key)
		if err != nil {
			return nil, err
		}
		token.TokenInstance = jwsToken
		break
	case common.JWE:
		jweToken, err := jwe.New(alg, claims, key)
		if err != nil {
			return nil, err
		}
		token.TokenInstance = jweToken
		break
	}

	return token, nil
}

func Encode(t *common.Token) ([]byte, error) {
	if t.Raw == nil || t.TokenType == "" {
		return nil, errors.New("invalid token. make sure you call New before you call Encode")
	}

	var err error
	switch t.TokenType {
	case common.JWS:
		tokenInstance, ok := t.TokenInstance.(*jws.Token)
		if !ok {
			return nil, errors.New("invalid token")
		}
		t.Raw, err = tokenInstance.Encode()
	case common.JWE:
		tokenInstance, ok := t.TokenInstance.(*jwe.Token)
		if !ok {
			return nil, errors.New("invalid token")
		}
		t.Raw, err = tokenInstance.Encode()
	}

	if err != nil {
		return nil, err
	}

	return t.Raw, nil
}

func Decode(tokenString string, key []byte) (*common.Token, error) {
	token := common.Token{Raw: []byte(tokenString)}
	jwtParts := strings.Split(tokenString, ".")
	var err error

	switch len(jwtParts) {
	case 3:
		token.TokenType = common.JWS
		jwsToken := new(jws.Token)
		jwsToken.Key = key
		token.TokenInstance = jwsToken
		err = jwsToken.Decode(jwtParts)
		if err != nil {
			return nil, err
		}
		token.Claims = jwsToken.Payload.ClaimSet
	case 5:
		token.TokenType = common.JWE
		tokenInstance, ok := token.TokenInstance.(*jwe.Token)
		if !ok {
			return nil, errors.New("invalid token")
		}

		err := tokenInstance.Decode(jwtParts)
		if err != nil {
			return nil, err
		}
	default:
		return nil, errors.New("invalid JWT format: unexpected number of parts")
	}

	return &token, nil
}

func Validate(t *common.Token) (bool, error) {
	if t.Raw == nil {
		return false, errors.New("jwt token is empty - you must call decode before validate")
	}

	switch t.TokenType {
	case common.JWS:
		tokenInstance, ok := t.TokenInstance.(*jws.Token)
		if !ok {
			return false, errors.New("invalid token")
		}
		return tokenInstance.Validate()
	case common.JWE:
		log.Fatal("JWE Not Implemented")
	}

	return false, errors.New("unable to decode - please check algorithm")
}
