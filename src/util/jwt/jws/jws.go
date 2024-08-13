package jws

import (
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/bmwadforth-com/armor-go/src/util/jwt/common"
	"time"
)

type SignFunc func(t *Token, signingInput []byte) ([]byte, error)
type ValidateFunc func(t *Token) (bool, error)

type Token struct {
	Header    common.Header
	Payload   common.Payload
	Signature common.Signature
	SignFunc
	ValidateFunc
	Key []byte
	Raw string
}

func New(alg common.AlgorithmType, claims common.ClaimSet, key []byte) (*Token, error) {
	t := new(Token)
	t.Header = common.Header{
		Data: map[string]interface{}{
			"alg": alg,
			"typ": "JWT",
		},
		Metadata: &common.Metadata{},
	}
	t.Payload = common.Payload{
		Data:     claims,
		Metadata: &common.Metadata{},
	}
	t.Signature = common.Signature{
		Metadata: &common.Metadata{},
	}
	t.SignFunc = getJwsSignFunc(alg)
	t.ValidateFunc = getJwsValidateFunc(alg)
	t.Key = key
	t.Raw = ""

	return t, nil
}

func (t *Token) Encode() (string, error) {
	var err error
	_, err = t.Header.Serialize()
	if err != nil {
		return "", fmt.Errorf("failed to encode header: %w", err)
	}
	_, err = t.Payload.Serialize()
	if err != nil {
		return "", fmt.Errorf("failed to encode payload: %w", err)
	}

	dataToSign := fmt.Sprintf("%s.%s", t.Header.Metadata.Base64, t.Payload.Metadata.Base64)
	signature, err := t.SignFunc(t, []byte(dataToSign))
	if err != nil {
		return "", fmt.Errorf("failed to sign JWT: %w", err)
	}
	signatureB64 := base64.RawURLEncoding.EncodeToString(signature)
	t.Signature.Metadata = &common.Metadata{
		Bytes:  signature,
		Base64: signatureB64,
	}

	t.Raw = fmt.Sprintf("%s.%s.%s", t.Header.Metadata.Base64, t.Payload.Metadata.Base64, t.Signature.Metadata.Base64)

	return t.Raw, nil
}

func (t *Token) Decode(parts []string) error {
	headerBytes := []byte(parts[0])
	payloadBytes := []byte(parts[1])
	signatureBytes := []byte(parts[2])
	_, err := t.Header.Deserialize(headerBytes)
	if err != nil {
		return fmt.Errorf("failed to decode JWS header: %w", err)
	}

	_, err = t.Payload.Deserialize(payloadBytes)
	if err != nil {
		return fmt.Errorf("failed to decode JWS payload: %w", err)
	}

	decodedSignature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return fmt.Errorf("failed to decode JWS signature: %w", err)
	}

	t.Signature.Metadata = &common.Metadata{
		Bytes:  decodedSignature,
		Base64: parts[2],
	}

	alg, err := t.Header.GetAlgorithm()
	if err != nil {
		return err
	}
	t.Raw = fmt.Sprintf("%s.%s.%s", headerBytes, payloadBytes, signatureBytes)
	t.SignFunc = getJwsSignFunc(alg)
	t.ValidateFunc = getJwsValidateFunc(alg)

	return nil
}

func (t *Token) Validate() (bool, error) {
	if t.ValidateFunc == nil {
		return false, errors.New("unable to verify data without a validating function defined. Please make sure you have invoked Decode before invoking Validate")
	}

	valid, err := t.ValidateFunc(t)
	if err != nil {
		return false, err
	}

	//TODO: ValidateJws more claims
	exp, ok := t.Payload.Data[string(common.ExpirationTime)]
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
