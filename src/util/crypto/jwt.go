package crypto

import (
	"github.com/bmwadforth-com/armor-go/src/util"
	"github.com/bmwadforth-com/armor-go/src/util/jwt"
	"github.com/bmwadforth-com/armor-go/src/util/jwt/common"
	"time"
)

func NewBearerToken(signingKey string) []byte {
	key := []byte(signingKey)

	claims := common.NewClaimSet()
	claims.Add(string(common.Audience), "web-template")
	claims.Add(string(common.Subject), "web-template")
	claims.Add(string(common.IssuedAt), time.Now())

	token, err := jwt.New(common.AlgorithmSuite{
		AlgorithmType: common.HS256,
	}, claims, key)
	if err != nil {
		util.LogError("unable to create token: %v", err)
		return nil
	}

	tokenBytes, err := jwt.Encode(token)
	if err != nil {
		util.LogError("unable to encode token: %v", err)
		return nil
	}

	return tokenBytes
}

func ValidateBearerToken(tokenString string, signingKey string) bool {
	key := []byte(signingKey)

	token, err := jwt.Decode(tokenString, key)
	if err != nil {
		util.LogError("unable to parse token: %v", err)
		return false
	}

	_, err = jwt.Validate(token)
	if err != nil {
		util.LogError("unable to validate token: %v", err)
		return false
	}

	return true
}

func GetTokenClaims(tokenString string, signingKey string) map[string]interface{} {
	key := []byte(signingKey)

	token, err := jwt.Decode(tokenString, key)
	if err != nil {
		util.LogError("unable to parse token claims: %v", err)
		return nil
	}

	return token.Claims
}
