package jwt

import (
	"github.com/bmwadforth-com/armor-go/src/util/jwt/common"
	"github.com/bmwadforth-com/armor-go/src/util/jwt/jwe"
	"github.com/bmwadforth-com/armor-go/src/util/jwt/jws"
)

type TokenBuilder struct {
	Claims common.ClaimSet

	token    *common.Token
	algSuite common.AlgorithmSuite
}

func (b *TokenBuilder) NewJWEToken(suite common.AlgorithmSuite, key []byte) *TokenBuilder {
	token, err := newToken(common.JWE, suite, common.ClaimSet{}, key)
	if err != nil {
		return nil
	}

	b.token = token
	b.token.TokenType = common.JWE
	b.algSuite = suite

	return b
}

func (b *TokenBuilder) NewJWSToken(algorithmType common.AlgorithmType, key []byte) *TokenBuilder {
	suite := common.AlgorithmSuite{
		AlgorithmType: algorithmType,
	}

	token, err := newToken(common.JWS, suite, common.ClaimSet{}, key)
	if err != nil {
		return nil
	}

	b.token = token
	b.token.TokenType = common.JWS
	b.algSuite = suite

	return b
}

func (b *TokenBuilder) AddClaims(claims common.ClaimSet) *TokenBuilder {
	b.Claims = claims

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

func (b *TokenBuilder) Serialize() (string, error) {

	return "", nil
}
