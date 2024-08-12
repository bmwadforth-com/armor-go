package jwt

import (
	"errors"
	"fmt"
	jwt "github.com/bmwadforth-com/armor-go/src/util/jwt"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestEncodeHMAC(t *testing.T) {
	key := []byte("TEST")
	claims := jwt.NewClaimSet()
	err := claims.Add(string(jwt.Audience), "developers")
	if err != nil {
		t.Fatal(err)
	}

	token, err := jwt.New(jwt.HS256, claims, key)
	if err != nil {
		t.Fatal(err)
	}

	encodedBytes, err := jwt.Encode(token)
	if err != nil {
		t.Fatal(err)
	}

	fmt.Println(string(encodedBytes))
}

func TestDecodeHMAC(t *testing.T) {
	key := []byte("TEST")
	tokenString := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJkZXZlbG9wZXJzIn0.4kNVyvKLfe6fuioUgM3rbWZ2PRQXRwYcC0c6cCQclGo"

	token, err := jwt.Decode(tokenString, key)
	if err != nil {
		t.Fatal(err)
	}

	if token.Claims[string(jwt.Audience)] != "developers" {
		t.Fatal(errors.New("claims not decoded correctly"))
	}
}

func TestValidateHMAC(t *testing.T) {
	key := []byte("TEST")
	tokenString := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJkZXZlbG9wZXJzIn0.4kNVyvKLfe6fuioUgM3rbWZ2PRQXRwYcC0c6cCQclGo"

	token, err := jwt.Decode(tokenString, key)
	if err != nil {
		t.Fatal(err)
	}

	_, err = jwt.Validate(token)
	if err != nil {
		t.Fatal(err)
	}
}

func TestDecodesOrderCorrectly(t *testing.T) {
	key := []byte("TEST")
	tokenString := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJkZXZlbG9wZXJzIiwiZGF0YSI6eyJmaXJzdF9uYW1lIjoiQnJhbm5vbiIsImxhc3RfbmFtZSI6IldhZGZvcnRoIn19.jEdsKOemSNO69yjItOROWNwPU2tvwrCG1H_rdLQRtzg"

	token, err := jwt.Decode(tokenString, key)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, tokenString, string(token.Raw))
}
