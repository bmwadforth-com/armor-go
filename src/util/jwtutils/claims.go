package jwt

import (
	"encoding/base64"
	"encoding/json"
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

func getClaims(payloadPart string) (ClaimSet, error) {
	decodedPayload, err := base64.RawURLEncoding.DecodeString(payloadPart)
	claimSet := NewClaimSet()
	if err != nil {
		return claimSet, fmt.Errorf("failed to decode payload: %w", err)
	}

	var claims map[string]interface{}
	if err := json.Unmarshal(decodedPayload, &claims); err != nil {
		return claimSet, fmt.Errorf("failed to unmarshal payload JSON: %w", err)
	}

	for key, value := range claims {
		claimSet.Claims[key] = value
	}

	return claimSet, nil
}
