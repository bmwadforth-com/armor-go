package cryptoutils

import (
	"fmt"
	"github.com/bmwadforth/jwt"
	"time"
)

func NewBearerToken(signingKey string) []byte {
	key := []byte(signingKey)

	claims := jwt.NewClaimSet()
	claims.Add(string(jwt.Audience), "web-template")
	claims.Add(string(jwt.Subject), "web-template")
	claims.Add(string(jwt.IssuedAt), time.Now())

	//Create new HS256 token, set claims and key
	token, err := jwt.New(jwt.HS256, claims, key)
	if err != nil {
		fmt.Println(err.Error())
		return nil
	}

	//Encode token
	tokenBytes, err := token.Encode()
	if err != nil {
		fmt.Println(err.Error())
		return nil
	}

	return tokenBytes
}

func ValidateBearerToken(tokenString string, signingKey string) bool {
	key := []byte(signingKey)

	//Parse token string
	token, err := jwt.Parse(tokenString, key)
	if err != nil {
		fmt.Println(err.Error())
		return false
	}

	//Validate token
	_, err = jwt.Validate(token)
	if err != nil {
		fmt.Println(err.Error())
		return false
	}

	return true
}

func GetTokenClaims(tokenString string, signingKey string) map[string]interface{} {
	key := []byte(signingKey)

	//Parse token string
	token, err := jwt.Parse(tokenString, key)
	if err != nil {
		fmt.Println(err.Error())
		return nil
	}

	return token.Claims
}
