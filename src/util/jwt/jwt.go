package jwt

import (
	"errors"
	"github.com/bmwadforth-com/armor-go/src/util/jwt/common"
	"github.com/bmwadforth-com/armor-go/src/util/jwt/jwe"
	"github.com/bmwadforth-com/armor-go/src/util/jwt/jws"
	"strings"
)

// newToken creates a new token of the specified type (JWS or JWE) with the given algorithm suite, claims, and key.
//
// Parameters:
//   - tokenType: The type of token to create (common.JWS or common.JWE).
//   - alg: The AlgorithmSuite defining the cryptographic algorithms to be used for signing/encryption.
//   - claims: The set of claims to be included in the token payload.
//   - key: The key (byte slice) to be used for signing/encryption operations.
//
// Returns:
//   - A pointer to a common.Token structure representing the newly created token.
//   - An error if there's an issue creating the token, such as an invalid token type or algorithm.
//
// This function performs the following steps:
// 1. Validates the token type. If it's empty, returns an error.
// 2. Initializes a new common.Token structure with the provided token type, metadata, and claims.
// 3. Switches on the token type:
//   - If JWS (JSON Web Signature):
//   - Creates a new jws.Token using the algorithm type from the suite, the claims, and the key.
//   - Sets the common.Token's TokenInstance to the newly created jws.Token.
//   - If JWE (JSON Web Encryption):
//   - Creates a new jwe.Token using the algorithm suite, the claims, and the key.
//   - Sets the common.Token's TokenInstance to the newly created jwe.Token.
//  4. Returns the created token and a nil error if successful, or a nil token and the
//     corresponding error if there was an issue during token creation.
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

// decodeToken decodes a JWT (JSON Web Token) string into a common.Token structure.
//
// Parameters:
//   - tokenString: The string representation of the JWT to be decoded.
//   - key: The key (byte slice) used for decoding the token.
//     For JWS, this is the verification key; for JWE, it's the decryption key.
//
// Returns:
// - A pointer to a common.Token structure containing the decoded token information.
// - An error if there's an issue decoding the token or if the token format is invalid.
//
// This function performs the following steps:
// 1. Initializes a common.Token structure with the base64 representation of the token string.
// 2. Splits the token string into its constituent parts using "." as the delimiter.
// 3. Based on the number of parts:
//   - If 3 parts, assumes it's a JWS (JSON Web Signature) token:
//   - Creates a new jws.Token and sets its key.
//   - Decodes the token using the jws.Token Decode method.
//   - Sets the common.Token's TokenType to JWS and its Claims to the decoded payload data.
//   - If 5 parts, assumes it's a JWE (JSON Web Encryption) token:
//   - Creates a new jwe.Token and sets its private key.
//   - Decodes the token using the jwe.Token Decode method.
//   - Sets the common.Token's TokenType to JWE.
//   - Otherwise, returns an error indicating an invalid JWT format.
//     4. Returns the decoded token and a nil error if successful, or a nil token and the
//     corresponding error if there was an issue during decoding.
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
