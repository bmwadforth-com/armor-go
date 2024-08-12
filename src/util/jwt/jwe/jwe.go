package jwe

import (
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/bmwadforth-com/armor-go/src/util/jwt/common"
	"strings"
)

type SignFunc func(t *Token, signingInput []byte) ([]byte, error)
type ValidateFunc func(t *Token) (bool, error)

type Token struct {
	Header  common.Header
	Payload common.Payload
	SignFunc
	ValidateFunc
	Raw []byte

	encryptedKey []byte // Encrypt the CEK with the recipient's public key using the "alg" to produce the JWE Encrypted Key.
	iv           []byte
	cipherText   []byte
	authTag      []byte
	publicKey    []byte
	cek          []byte
}

func New(alg common.AlgorithmSuite, claims common.ClaimSet, publicKey []byte) (*Token, error) {
	t := new(Token)
	t.Header = common.Header{
		Properties: map[string]interface{}{
			"alg": alg.AlgorithmType,
			"enc": alg.AuthAlgorithmType,
			"typ": "JWT",
		},
		Raw: []byte{},
	}
	t.Payload = common.Payload{
		ClaimSet: claims,
		Raw:      []byte{},
	}
	t.SignFunc = getJweSignFunc(alg)
	//TODO: t.ValidateFunc = getJweValidateFunc(alg)

	t.Raw = []byte{}
	t.publicKey = publicKey

	return t, nil
}

func (t *Token) Encode() ([]byte, error) {
	var err error
	t.Header.Raw, err = t.Header.ToBase64()
	if err != nil {
		return nil, fmt.Errorf("failed to encode header: %w", err)
	}

	t.Payload.Raw, err = t.Payload.MarshalJSON()
	if err != nil {
		return nil, fmt.Errorf("failed to encode payload: %w", err)
	}

	_, err = t.SignFunc(t, t.Payload.Raw)
	if err != nil {
		return nil, fmt.Errorf("failed to sign JWT: %w", err)
	}

	parts := []string{
		fmt.Sprintf("%s", t.Header.Raw),
		base64.RawURLEncoding.EncodeToString(t.encryptedKey),
		base64.RawURLEncoding.EncodeToString(t.iv),
		base64.RawURLEncoding.EncodeToString(t.cipherText),
		"", // Empty authentication tag (not calculated here)
	}

	jwe := strings.Join(parts, ".")
	t.Raw = []byte(jwe)

	return t.Raw, nil
}

func (t *Token) Decode(parts []string) error {
	return errors.New("jwe decode not implemented")
}

func (t *Token) Validate() (bool, error) {
	return false, errors.New("jwe validate not implemented")
}
