package jwt

import (
	"github.com/bmwadforth-com/armor-go/src/util/jwt/common"
	"github.com/bmwadforth-com/armor-go/src/util/jwt/jwe"
	"github.com/bmwadforth-com/armor-go/src/util/jwt/jws"
)

type TokenBuilder struct {
	token    *common.Token
	algSuite common.AlgorithmSuite
}

func DecodeToken(tokenString string, key []byte) (*TokenBuilder, error) {
	token, err := decodeToken(tokenString, key)
	if err != nil {
		return nil, err
	}

	b := new(TokenBuilder)
	b.token = token
	switch b.token.TokenType {
	case common.JWE:
		instance := b.token.TokenInstance.(*jwe.Token)
		algorithm, err := instance.Header.GetAlgorithm()
		if err != nil {
			return nil, err
		}

		encryptionAlgorithm, err := instance.Header.GetEncryptionAlgorithm()
		if err != nil {
			return nil, err
		}

		b.algSuite = common.AlgorithmSuite{
			AlgorithmType:     algorithm,
			AuthAlgorithmType: encryptionAlgorithm,
		}
	case common.JWS:
		instance := b.token.TokenInstance.(*jws.Token)
		algorithm, err := instance.Header.GetAlgorithm()
		if err != nil {
			return nil, err
		}

		b.algSuite = common.AlgorithmSuite{
			AlgorithmType: algorithm,
		}
	}

	return b, nil
}

func NewJWEToken(suite common.AlgorithmSuite, key []byte) *TokenBuilder {
	token, err := newToken(common.JWE, suite, common.ClaimSet{}, key)
	if err != nil {
		return nil
	}

	b := new(TokenBuilder)
	b.token = token
	b.token.TokenType = common.JWE
	b.algSuite = suite

	return b
}

func NewJWSToken(algorithmType common.AlgorithmType, key []byte) *TokenBuilder {
	suite := common.AlgorithmSuite{
		AlgorithmType: algorithmType,
	}

	token, err := newToken(common.JWS, suite, common.ClaimSet{}, key)
	if err != nil {
		return nil
	}

	b := new(TokenBuilder)
	b.token = token
	b.token.TokenType = common.JWS
	b.algSuite = suite

	return b
}

func (b *TokenBuilder) GetClaims() common.ClaimSet {
	switch b.token.TokenType {
	case common.JWE:
		instance := b.token.TokenInstance.(*jwe.Token)
		return instance.Payload.Data
	case common.JWS:
		instance := b.token.TokenInstance.(*jws.Token)
		return instance.Payload.Data
	}

	return nil
}

func (b *TokenBuilder) AddClaims(claims common.ClaimSet) *TokenBuilder {
	switch b.token.TokenType {
	case common.JWE:
		instance := b.token.TokenInstance.(*jwe.Token)
		instance.Payload.Data = claims
		instance.Payload.Serialize()
		break
	case common.JWS:
		instance := b.token.TokenInstance.(*jws.Token)
		instance.Payload.Data = claims
		instance.Payload.Serialize()
		break
	}

	return b
}

func (b *TokenBuilder) Validate() (bool, error) {
	return validateToken(b.token)
}

func (b *TokenBuilder) Serialize() (string, error) {
	encode, err := b.token.TokenInstance.Encode()
	if err != nil {
		return "", err
	}

	return string(encode), nil
}
