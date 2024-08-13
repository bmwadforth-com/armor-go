package jwe

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"
	"github.com/bmwadforth-com/armor-go/src/util/crypto"
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
	privateKey, err := crypto.DecodeRsaPrivateKey(t.PrivateKey)
	if err != nil {
		return false, err
	}

	plaintext, err := decryptJWE(t, privateKey)
	if err != nil {
		return false, err
	}

	_, err = t.Payload.Deserialize(plaintext)
	if err != nil {
		return false, err
	}

	return true, nil
}

func decryptJWE(t *Token, privateKey *rsa.PrivateKey) ([]byte, error) {
	parts := strings.Split(string(t.Raw), ".")
	if len(parts) != 5 {
		return nil, fmt.Errorf("invalid JWE format")
	}

	cek, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, privateKey, t.encryptedKey, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt CEK: %w", err)
	}

	block, err := aes.NewCipher(cek)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	ciphertextWithTag := append(t.cipherText, t.authTag...)
	plaintext, err := aesGCM.Open(nil, t.iv, ciphertextWithTag, t.Header.Metadata.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt payload: %w", err)
	}

	return plaintext, nil
}
