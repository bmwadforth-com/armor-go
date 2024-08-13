package jwt

import (
	"errors"
	"github.com/bmwadforth-com/armor-go/src/util/jwt/common"
	"github.com/bmwadforth-com/armor-go/src/util/jwt/jwe"
	"github.com/bmwadforth-com/armor-go/src/util/jwt/jws"
	"strings"
)

func newToken(tokenType common.TokenType, alg common.AlgorithmSuite, claims common.ClaimSet, key []byte) (*common.Token, error) {
	if tokenType == "" {
		return nil, errors.New("invalid algorithm")
	}

	token := new(common.Token)
	token.TokenType = tokenType
	token.Metadata = &common.Metadata{}
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

func encodeToken(t *common.Token) ([]byte, error) {
	if t.Metadata == nil || t.TokenType == "" {
		return nil, errors.New("invalid token. make sure you call newToken before you call encodeToken")
	}

	var err error
	switch t.TokenType {
	case common.JWS:
		tokenInstance, ok := t.TokenInstance.(*jws.Token)
		if !ok {
			return nil, errors.New("invalid token")
		}
		t.Metadata.Bytes, err = tokenInstance.Encode()
	case common.JWE:
		tokenInstance, ok := t.TokenInstance.(*jwe.Token)
		if !ok {
			return nil, errors.New("invalid token")
		}
		t.Metadata.Bytes, err = tokenInstance.Encode()
	}

	if err != nil {
		return nil, err
	}

	return t.Metadata.Bytes, nil
}

func decodeToken(tokenString string, key []byte) (*common.Token, error) {
	var err error
	token := common.Token{Metadata: &common.Metadata{
		Base64: tokenString,
	}}
	jwtParts := strings.Split(tokenString, ".")

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
		token.Claims = jwsToken.Payload.Data
	case 5:
		token.TokenType = common.JWE
		jweToken := new(jwe.Token)
		jweToken.PrivateKey = key
		token.TokenInstance = jweToken
		err = jweToken.Decode(jwtParts)
		if err != nil {
			return nil, err
		}
	default:
		return nil, errors.New("invalid JWT format: unexpected number of parts")
	}

	return &token, nil
}

func validateToken(t *common.Token) (bool, error) {
	if t.Metadata == nil {
		return false, errors.New("jwt token is empty - you must call decode before validate")
	}

	switch t.TokenType {
	case common.JWS:
		tokenInstance, ok := t.TokenInstance.(*jws.Token)
		if !ok {
			return false, errors.New("invalid token")
		}
		ok, err := tokenInstance.Validate()
		if !ok {
			return false, err
		}
	case common.JWE:
		tokenInstance, ok := t.TokenInstance.(*jwe.Token)
		if !ok {
			return false, errors.New("invalid token")
		}
		ok, err := tokenInstance.Validate()
		if !ok {
			return false, err
		}
		t.Claims = tokenInstance.Payload.Data
	}

	return true, nil
}
