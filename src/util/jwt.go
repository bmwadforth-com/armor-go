package util

import (
	"github.com/bmwadforth-com/armor-go/src/util/jwt"
	"github.com/bmwadforth-com/armor-go/src/util/jwt/common"
	"time"
)

func NewBearerToken(signingKey string) ([]byte, error) {
	key := []byte(signingKey)

	claims := common.NewClaimSet()
	claims.Add(string(common.Audience), "web-template")
	claims.Add(string(common.Subject), "web-template")
	claims.Add(string(common.IssuedAt), time.Now())

	token, err := jwt.New(common.AlgorithmSuite{
		AlgorithmType: common.HS256,
	}, claims, key)
	if err != nil {
		return nil, err
	}

	tokenBytes, err := jwt.Encode(token)
	if err != nil {
		return nil, err
	}

	return tokenBytes, nil
}

func ValidateBearerToken(tokenString string, signingKey string) (bool, error) {
	key := []byte(signingKey)

	token, err := jwt.Decode(tokenString, key)
	if err != nil {
		return false, err
	}

	_, err = jwt.Validate(token)
	if err != nil {
		return false, err
	}

	return true, nil
}

func GetTokenClaims(tokenString string, signingKey string) (map[string]interface{}, error) {
	key := []byte(signingKey)

	token, err := jwt.Decode(tokenString, key)
	if err != nil {
		return nil, err
	}

	return token.Claims, nil
}
