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
	token, err := jwt.NewJWSToken(common.HS256, key).AddClaims(claims).Serialize()
	if err != nil {
		return nil, err
	}

	return []byte(token), nil
}

func ValidateBearerToken(tokenString string, signingKey string) (bool, error) {
	key := []byte(signingKey)

	tokenBuilder, err := jwt.DecodeToken(tokenString, key)
	if err != nil {
		return false, err
	}

	_, err = tokenBuilder.Validate()
	if err != nil {
		return false, err
	}

	return true, nil
}

func GetTokenClaims(tokenString string, signingKey string) (map[string]interface{}, error) {
	key := []byte(signingKey)

	tokenBuilder, err := jwt.DecodeToken(tokenString, key)
	if err != nil {
		return nil, err
	}

	return tokenBuilder.GetClaims(), nil
}
