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

// DecodeToken decodes a token string using the provided key and returns a TokenBuilder.
//
// Parameters:
//   - tokenString: The string representation of the token to be decoded.
//   - key: The key (byte slice) used for decoding the token.
//
// Returns:
//   - A pointer to a TokenBuilder containing the decoded token information and algorithm suite.
//   - An error if there's an issue decoding the token or extracting algorithm details.
//
// This function performs the following steps:
// 1. Decodes the token string using the `decodeToken` helper function and the provided key.
// 2. Creates a new TokenBuilder and sets its `token` field to the decoded token.
// 3. Switches on the token type:
//   - If JWE (JSON Web Encryption):
//   - Extracts the algorithm and encryption algorithm from the token header.
//   - Sets the TokenBuilder's `algSuite` with the extracted algorithms.
//   - If JWS (JSON Web Signature):
//   - Extracts the algorithm from the token header.
//   - Sets the TokenBuilder's `algSuite` with the extracted algorithm.
//     4. Returns the TokenBuilder and a nil error if successful, or a nil TokenBuilder and the
//     corresponding error if there was an issue during decoding or algorithm extraction.
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
	return b.token.TokenInstance.Validate()
}

func (b *TokenBuilder) Serialize() (string, error) {
	return b.token.TokenInstance.Encode()
}
