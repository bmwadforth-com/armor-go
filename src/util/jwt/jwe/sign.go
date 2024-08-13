package jwe

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"github.com/bmwadforth-com/armor-go/src/util/crypto"
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
	publicKey, err := crypto.DecodeRsaPublicKey(t.PublicKey)
	if err != nil {
		return nil, err
	}

	keySize, err := t.Header.GetAuthAlgorithm()
	if err != nil {
		return nil, err
	}

	cek, err := newContentEncryptionKey(keySize)
	if err != nil {
		return nil, err
	}

	ciphertext, nonce, authTag, err := crypto.EncryptAESGCM(cek, plaintext, t.Header.Raw)
	if err != nil {
		return nil, err
	}

	label := []byte("")
	encryptedKey, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, publicKey, cek, label)
	if err != nil {
		return nil, err
	}

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
