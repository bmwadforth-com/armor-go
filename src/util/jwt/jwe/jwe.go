package jwe

import (
	"errors"
	"github.com/bmwadforth-com/armor-go/src/util/jwt/common"
)

type Token struct {
	common.Header
	EncryptedKey []byte // Encrypt the CEK with the recipient's public key using the "alg" to produce the JWE Encrypted Key.

	iv         []byte
	cipherText []byte
	authTag    []byte
	publicKey  []byte
	cek        []byte
}

func New(alg common.AlgorithmSuite, claims common.ClaimSet, publicKey []byte) (*Token, error) {
	t := new(Token)
	t.Header = common.Header{
		Properties: map[string]interface{}{
			"alg": alg.AlgorithmType,
			"enc": alg.AuthAlgorithmType,
		},
		Raw: []byte{},
	}

	t.Raw = []byte{}
	t.publicKey = publicKey

	return t, nil
}

func (t *Token) Encode() ([]byte, error) {
	return nil, errors.New("jwe encode not implemented")
}

func (t *Token) Decode(parts []string) error {
	return errors.New("jwe decode not implemented")
}

func (t *Token) Validate() (bool, error) {
	return false, errors.New("jwe validate not implemented")
}
