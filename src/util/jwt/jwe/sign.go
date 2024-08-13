package jwe

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"github.com/bmwadforth-com/armor-go/src/util/jwt/common"
)

func getJweSignFunc(a common.AlgorithmSuite) SignFunc {
	switch a.AlgorithmType {
	case common.RSA_OAEP:
		switch a.AuthAlgorithmType {
		case common.A256GCM:
			return signRSAOAEPA256GCM
		}
	}

	return nil
}

func signRSAOAEPA256GCM(t *Token, plaintext []byte) ([]byte, error) {
	keySize, err := t.Header.GetAuthAlgorithm()
	if err != nil {
		return nil, err
	}

	cek, err := newContentEncryptionKey(keySize)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(t.PublicKey)
	if block == nil {
		return nil, errors.New("failed to parse PEM block containing the public key")
	}

	publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	rsaPublicKey := publicKey.(*rsa.PublicKey)

	label := []byte("")
	encryptedKey, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, rsaPublicKey, cek, label)
	if err != nil {
		return nil, err
	}

	aesBlock, err := aes.NewCipher(cek)
	if err != nil {
		return nil, err
	}
	aesGCM, err := cipher.NewGCM(aesBlock)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aesGCM.NonceSize())
	_, err = rand.Read(nonce)
	if err != nil {
		return nil, err
	}

	ciphertextWithTag := aesGCM.Seal(nil, nonce, plaintext, t.Header.Raw)
	tagSize := aesGCM.Overhead()
	ciphertext := ciphertextWithTag[:len(ciphertextWithTag)-tagSize]
	authTag := ciphertextWithTag[len(ciphertextWithTag)-tagSize:]

	t.encryptedKey = encryptedKey
	t.iv = nonce
	t.cipherText = ciphertext
	t.authTag = authTag

	return encryptedKey, nil
}

func newContentEncryptionKey(alg common.AuthAlgorithmType) ([]byte, error) {
	keySize := common.JweAuthAlgorithmSizeMap[alg]
	cek := make([]byte, keySize)
	_, err := rand.Read(cek)
	if err != nil {
		return nil, err
	}

	return cek, nil
}
