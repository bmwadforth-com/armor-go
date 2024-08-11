package jwtutils

import (
	"errors"
	"fmt"
	"github.com/bmwadforth-com/armor-go/src/util/jwtutils"
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

	encodedBytes, err := token.Encode()
	if err != nil {
		t.Fatal(err)
	}

	fmt.Println(string(encodedBytes))
}

func TestDecodeHMAC(t *testing.T) {
	key := []byte("TEST")
	tokenString := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJkZXZlbG9wZXJzIn0.4kNVyvKLfe6fuioUgM3rbWZ2PRQXRwYcC0c6cCQclGo"

	token, err := jwt.Parse(tokenString, key)
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

	token, err := jwt.Parse(tokenString, key)
	if err != nil {
		t.Fatal(err)
	}

	_, err = jwt.Validate(token)
	if err != nil {
		t.Fatal(err)
	}
}
