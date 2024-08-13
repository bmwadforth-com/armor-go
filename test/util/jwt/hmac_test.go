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

	token, err := jwt.new(common.AlgorithmSuite{
		AlgorithmType: common.HS256,
	}, claims, key)
	if err != nil {
		t.Fatal(err)
	}

	_, err = jwt.encodeToken(token)
	if err != nil {
		t.Fatal(err)
	}
}

func TestDecodeHMAC(t *testing.T) {
	key := []byte("TEST")
	tokenString := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJkZXZlbG9wZXJzIn0.4kNVyvKLfe6fuioUgM3rbWZ2PRQXRwYcC0c6cCQclGo"

	token, err := jwt.decodeToken(tokenString, key)
	if err != nil {
		t.Fatal(err)
	}

	if token.Claims[string(common.Audience)] != "developers" {
		t.Fatal(errors.New("claims not decoded correctly"))
	}
}

func TestValidateHMAC(t *testing.T) {
	key := []byte("TEST")
	tokenString := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJkZXZlbG9wZXJzIn0.4kNVyvKLfe6fuioUgM3rbWZ2PRQXRwYcC0c6cCQclGo"

	token, err := jwt.decodeToken(tokenString, key)
	if err != nil {
		t.Fatal(err)
	}

	_, err = jwt.validateToken(token)
	if err != nil {
		t.Fatal(err)
	}
}

func TestDecodesOrderCorrectly(t *testing.T) {
	key := []byte("TEST")
	tokenString := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJkZXZlbG9wZXJzIiwiZGF0YSI6eyJmaXJzdF9uYW1lIjoiQnJhbm5vbiIsImxhc3RfbmFtZSI6IldhZGZvcnRoIn19.jEdsKOemSNO69yjItOROWNwPU2tvwrCG1H_rdLQRtzg"

	token, err := jwt.decodeToken(tokenString, key)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, tokenString, string(token.Metadata))
}
