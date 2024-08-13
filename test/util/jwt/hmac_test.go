package jwt

import (
	"errors"
	"github.com/bmwadforth-com/armor-go/src/util/jwt"
	"github.com/bmwadforth-com/armor-go/src/util/jwt/common"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestEncodeHMAC(t *testing.T) {
	key := []byte("TEST")
	claims := common.NewClaimSet()
	err := claims.Add(string(common.Audience), "developers")
	if err != nil {
		t.Fatal(err)
	}

	tokenBuilder := jwt.NewJWSToken(common.HS256, key)

	_, err = tokenBuilder.AddClaims(claims).Serialize()
	if err != nil {
		t.Fatal(err)
	}
}

func TestDecodeHMAC(t *testing.T) {
	key := []byte("TEST")
	tokenString := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJkZXZlbG9wZXJzIn0.4kNVyvKLfe6fuioUgM3rbWZ2PRQXRwYcC0c6cCQclGo"

	tokenBuilder, err := jwt.DecodeToken(tokenString, key)
	if err != nil {
		t.Fatal(err)
	}

	if tokenBuilder.GetClaims()[string(common.Audience)] != "developers" {
		t.Fatal(errors.New("claims not decoded correctly"))
	}
}

func TestValidateHMAC(t *testing.T) {
	key := []byte("TEST")
	tokenString := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJkZXZlbG9wZXJzIn0.4kNVyvKLfe6fuioUgM3rbWZ2PRQXRwYcC0c6cCQclGo"

	tokenBuilder, err := jwt.DecodeToken(tokenString, key)
	if err != nil {
		t.Fatal(err)
	}

	_, err = tokenBuilder.Validate()
	if err != nil {
		t.Fatal(err)
	}
}

func TestDecodesOrderCorrectly(t *testing.T) {
	key := []byte("TEST")
	tokenString := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJkZXZlbG9wZXJzIiwiZGF0YSI6eyJmaXJzdF9uYW1lIjoiQnJhbm5vbiIsImxhc3RfbmFtZSI6IldhZGZvcnRoIn19.jEdsKOemSNO69yjItOROWNwPU2tvwrCG1H_rdLQRtzg"

	tokenBuilder, err := jwt.DecodeToken(tokenString, key)
	if err != nil {
		t.Fatal(err)
	}

	serializedToken, err := tokenBuilder.Serialize()
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, tokenString, serializedToken)
}
