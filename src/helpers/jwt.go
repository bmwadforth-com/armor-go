package helpers

import (
	"errors"
	"github.com/bmwadforth-com/armor-go/src/util"
	"github.com/bmwadforth-com/armor-go/src/util/jwt"
	"github.com/bmwadforth-com/armor-go/src/util/jwt/common"
	"net/http"
	"strings"
)

func NewHS256BearerToken(key string, claims common.ClaimSet) (string, error) {
	privateKey := []byte(key)
	tokenBuilder := jwt.NewJWSToken(common.HS256, privateKey)
	token, err := tokenBuilder.AddClaims(claims).Serialize()
	if err != nil {
		util.LogError("Failed to generate token: %v", err)
		return "", err
	}

	claimsSerialized, err := claims.MarshalJSON()
	if err != nil {
		util.LogError("Failed to serialize claims: %v", err)
		return "", err
	}

	util.LogInfo("new token generated with claims: %s", string(claimsSerialized))

	return token, nil
}

func ValidateHS256BearerToken(key string, tokenString string) bool {
	privateKey := []byte(key)

	tokenBuilder, err := jwt.DecodeToken(tokenString, privateKey)
	if err != nil {
		util.LogError("Failed to decode token: %v", err)
		return false
	}

	_, err = tokenBuilder.Validate()
	if err != nil {
		util.LogError("Failed to validate token: %v", err)
		return false
	}

	return true
}

func GetBearerTokenFromRequestHeader(req *http.Request) (string, error) {
	authHeader := req.Header.Get("Authorization")
	bearer := strings.Split(authHeader, "Bearer ")
	if len(bearer) == 2 {
		return bearer[1], nil
	} else {
		util.LogError("auth header is malformed")
		return "", errors.New("auth header is malformed")
	}
}

func GetClaimsFromToken(key string, tokenString string) map[string]interface{} {
	privateKey := []byte(key)

	tokenBuilder, err := jwt.DecodeToken(tokenString, privateKey)
	if err != nil {
		util.LogError("Failed to decode token: %v", err)
		return nil
	}

	return tokenBuilder.GetClaims()
}
