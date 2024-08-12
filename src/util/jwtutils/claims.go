package jwt

import (
	"errors"
	"fmt"
)

type ClaimSet struct {
	Claims map[string]interface{}
}
type RegisteredClaim string

const (
	Issuer         RegisteredClaim = "iss"
	Subject        RegisteredClaim = "sub"
	Audience       RegisteredClaim = "aud"
	ExpirationTime RegisteredClaim = "exp"
	NotBefore      RegisteredClaim = "nbf"
	IssuedAt       RegisteredClaim = "iat"
	JwtID          RegisteredClaim = "jti"
)

func NewClaimSet() ClaimSet {
	return ClaimSet{Claims: map[string]interface{}{}}
}

func (c *ClaimSet) Add(key string, value interface{}) error {
	_, found := c.Claims[key]
	if found {
		return errors.New("duplicate claims are forbidden")
	}

	c.Claims[key] = value

	return nil
}

func (c *ClaimSet) Remove(key string) error {
	_, found := c.Claims[key]
	if found {
		delete(c.Claims, key)
	} else {
		return errors.New(fmt.Sprintf("key: %s was not found in claim set", key))
	}

	return nil
}
