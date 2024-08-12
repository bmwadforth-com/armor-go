package jwt

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
)

type ClaimSet map[string]interface{}
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
	return ClaimSet{}
}

func (c *ClaimSet) Add(key string, value interface{}) error {
	_, found := (*c)[key]
	if found {
		return errors.New("duplicate claims are forbidden")
	}

	(*c)[key] = value

	return nil
}

func (c *ClaimSet) Remove(key string) error {
	_, found := (*c)[key]
	if found {
		delete(*c, key)
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
		claimSet[key] = value
	}

	return claimSet, nil
}

// MarshalJSON implements the json.Marshaler interface
func (c *ClaimSet) MarshalJSON() ([]byte, error) {
	keys := make([]string, 0, len(*c))
	for k := range *c {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	sortedClaims := make(map[string]interface{})
	for _, k := range keys {
		sortedClaims[k] = (*c)[k]
	}

	return json.Marshal(sortedClaims)
}

// UnmarshalJSON implements the json.Unmarshaler interface
func (c *ClaimSet) UnmarshalJSON(data []byte) error {
	var tempMap map[string]interface{}
	if err := json.Unmarshal(data, &tempMap); err != nil {
		return fmt.Errorf("failed to unmarshal JSON: %w", err)
	}

	if *c == nil {
		*c = make(map[string]interface{})
	} else {
		for k := range *c {
			delete(*c, k)
		}
	}

	for k, v := range tempMap {
		(*c)[k] = v
	}

	return nil
}
