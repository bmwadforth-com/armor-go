package jwe

import (
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/bmwadforth-com/armor-go/src/util/jwt/common"
	"strings"
	"time"
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
	PrivateKey   []byte
	PublicKey    []byte
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
	t.PublicKey = publicKey

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
	headerBytes := []byte(parts[0])
	t.Header.Raw = headerBytes
	_, err := t.Header.FromBase64(headerBytes)
	if err != nil {
		return fmt.Errorf("failed to decode JWS header: %w", err)
	}

	encryptedKeyBytes := []byte(parts[1])
	t.encryptedKey = encryptedKeyBytes

	ivBytes := []byte(parts[2])
	t.iv = ivBytes

	cipherTextBytes := []byte(parts[3])
	t.cipherText = cipherTextBytes

	alg, err := t.Header.GetAlgorithm()
	if err != nil {
		return err
	}

	authAlg, err := t.Header.GetAuthAlgorithm()
	if err != nil {
		return err
	}

	suite := common.AlgorithmSuite{
		AlgorithmType:     alg,
		AuthAlgorithmType: authAlg,
	}

	t.Raw = []byte(strings.Join(parts, "."))
	t.SignFunc = getJweSignFunc(suite)
	t.ValidateFunc = getJweValidateFunc(suite)

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
	exp, ok := t.Payload.ClaimSet[string(common.ExpirationTime)]
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
