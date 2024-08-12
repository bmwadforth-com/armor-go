package jwt

import (
	"encoding/base64"
	"errors"
	"fmt"
	"time"
)

type Header struct {
	Properties map[string]interface{}
	raw        []byte
}

type Payload struct {
	ClaimSet
	raw []byte
}

type Signature struct {
	raw []byte
}

type JwsToken struct {
	Header
	Payload
	Signature
	jwsSignFunc
	jwsValidateFunc
	key []byte
	raw []byte
}

func newJwsToken(alg AlgorithmType, claims ClaimSet, key []byte) (*JwsToken, error) {
	t := new(JwsToken)
	t.Header = Header{
		Properties: map[string]interface{}{
			"alg": alg,
			"typ": "JWT",
		},
		raw: []byte{},
	}
	t.Payload = Payload{
		ClaimSet: claims,
		raw:      []byte{},
	}
	t.Signature = Signature{
		raw: []byte{},
	}
	t.jwsSignFunc = getJwsSignFunc(alg)
	t.jwsValidateFunc = getJwsValidateFunc(alg)
	t.key = key
	t.raw = []byte{}

	return t, nil
}

func (t *JwsToken) encode() ([]byte, error) {
	var err error
	t.Header.raw, err = t.Header.toBase64()
	if err != nil {
		return nil, fmt.Errorf("failed to encode header: %w", err)
	}
	t.Payload.raw, err = t.Payload.toBase64()
	if err != nil {
		return nil, fmt.Errorf("failed to encode payload: %w", err)
	}

	dataToSign := fmt.Sprintf("%s.%s", t.Header.raw, t.Payload.raw)
	signature, err := t.jwsSignFunc(t, []byte(dataToSign))
	if err != nil {
		return nil, fmt.Errorf("failed to sign JWT: %w", err)
	}
	signatureB64 := base64.RawURLEncoding.EncodeToString(signature)
	t.Signature.raw = []byte(signatureB64)

	t.raw = []byte(fmt.Sprintf("%s.%s.%s", t.Header.raw, t.Payload.raw, t.Signature.raw))

	return t.raw, nil
}

func (t *JwsToken) decode(parts []string) error {
	_, err := t.Header.fromBase64([]byte(parts[0]))
	if err != nil {
		return fmt.Errorf("failed to decode JWS header: %w", err)
	}

	_, err = t.Payload.fromBase64([]byte(parts[1]))
	if err != nil {
		return fmt.Errorf("failed to decode JWS payload: %w", err)
	}

	t.Signature.raw = []byte(parts[2])

	return nil
}

func (t *JwsToken) validate() (bool, error) {
	if t.jwsValidateFunc == nil {
		return false, errors.New("unable to verify data without a validating function defined")
	}

	valid, err := t.jwsValidateFunc(t)
	if err != nil {
		return false, err
	}

	//TODO: ValidateJws more claims
	exp, ok := t.Claims[string(ExpirationTime)]
	if ok {
		claim := exp.(string)
		expiration, err := time.Parse(time.RFC3339, claim)
		if err != nil {
			return false, err
		}

		if expiration.Before(time.Now()) {
			return false, errors.New("token has expired")
		}
	}

	return valid, nil
}
