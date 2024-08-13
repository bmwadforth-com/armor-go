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
	Raw        string
	PrivateKey []byte
	PublicKey  []byte

	encryptedKey []byte
	iv           []byte
	cipherText   []byte
	authTag      []byte
	cek          []byte
}

func New(alg common.AlgorithmSuite, claims common.ClaimSet, publicKey []byte) (*Token, error) {
	t := new(Token)
	t.Header = common.Header{
		Data: map[string]interface{}{
			"alg": alg.AlgorithmType,
			"enc": alg.AuthAlgorithmType,
			"typ": "JWT",
		},
		Metadata: &common.Metadata{},
	}
	t.Payload = common.Payload{
		Data:     claims,
		Metadata: &common.Metadata{},
	}
	t.SignFunc = getJweSignFunc(alg)
	t.ValidateFunc = getJweValidateFunc(alg)

	t.Raw = ""
	t.PublicKey = publicKey

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

	_, err = t.SignFunc(t, t.Payload.Metadata.Bytes)
	if err != nil {
		return "", fmt.Errorf("failed to sign JWT: %w", err)
	}

	parts := []string{
		fmt.Sprintf("%s", t.Header.Metadata),
		base64.RawURLEncoding.EncodeToString(t.encryptedKey),
		base64.RawURLEncoding.EncodeToString(t.iv),
		base64.RawURLEncoding.EncodeToString(t.cipherText),
		base64.RawURLEncoding.EncodeToString(t.authTag),
	}

	jwe := strings.Join(parts, ".")
	t.Raw = jwe

	return t.Raw, nil
}

func (t *Token) Decode(parts []string) error {
	headerBytes := []byte(parts[0])
	_, err := t.Header.Deserialize(headerBytes)
	if err != nil {
		return fmt.Errorf("failed to decode JWS header: %w", err)
	}

	encryptedKeyBytes, _ := base64.RawURLEncoding.DecodeString(parts[1])
	t.encryptedKey = encryptedKeyBytes

	ivBytes, _ := base64.RawURLEncoding.DecodeString(parts[2])
	t.iv = ivBytes

	cipherTextBytes, _ := base64.RawURLEncoding.DecodeString(parts[3])
	t.cipherText = cipherTextBytes

	authTagBytes, _ := base64.RawURLEncoding.DecodeString(parts[4])
	t.authTag = authTagBytes

	alg, err := t.Header.GetAlgorithm()
	if err != nil {
		return err
	}

	authAlg, err := t.Header.GetEncryptionAlgorithm()
	if err != nil {
		return err
	}

	suite := common.AlgorithmSuite{
		AlgorithmType:     alg,
		AuthAlgorithmType: authAlg,
	}

	t.Raw = strings.Join(parts, ".")
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
