package jwe

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"github.com/bmwadforth-com/armor-go/src/util/jwt/common"
	"strings"
)

func getJweValidateFunc(a common.AlgorithmSuite) ValidateFunc {
	switch a.AlgorithmType {
	case common.RSA_OAEP:
		switch a.AuthAlgorithmType {
		case common.A256GCM:
			return validateRSAOAEPA256GCM
		}
	}

	return nil
}

func validateRSAOAEPA256GCM(t *Token) (bool, error) {
	pemBlock, _ := pem.Decode(t.PrivateKey)
	if pemBlock == nil {
		return false, fmt.Errorf("failed to parse PEM block containing the private key")
	}
	privateKey, err := x509.ParsePKCS8PrivateKey(pemBlock.Bytes)
	if err != nil {
		return false, fmt.Errorf("failed to parse private key: %w", err)

	}

	parts := strings.Split(string(t.Raw), ".")
	if len(parts) != 5 {
		return false, fmt.Errorf("invalid JWE format")
	}

	cek, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, privateKey.(*rsa.PrivateKey), t.encryptedKey, nil)
	if err != nil {
		return false, fmt.Errorf("failed to decrypt CEK: %w", err)
	}

	block, err := aes.NewCipher(cek)
	if err != nil {
		return false, fmt.Errorf("failed to create AES cipher: %w", err)
	}
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return false, fmt.Errorf("failed to create GCM: %w", err)
	}

	plaintext, err := aesGCM.Open(nil, t.iv, t.cipherText, nil)
	if err != nil {
		return false, fmt.Errorf("failed to decrypt payload: %w", err)
	}

	t.Payload.Raw = plaintext
	err = t.Payload.UnmarshalJSON(plaintext)
	if err != nil {
		return false, err
	}

	return true, nil
}
