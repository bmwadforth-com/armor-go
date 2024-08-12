package jwe

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"github.com/bmwadforth-com/armor-go/src/util/jwt/common"
	"log"
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

func signRSAOAEPA256GCM(t *Token, signingInput []byte) ([]byte, error) {
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
		panic("failed to parse PEM block containing the public key")
	}

	publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		panic(err)
	}
	rsaPublicKey := publicKey.(*rsa.PublicKey)

	label := []byte("")
	encryptedKey, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, rsaPublicKey, cek, label)
	if err != nil {
		log.Fatal(err)
	}

	aesBlock, err := aes.NewCipher(cek)
	if err != nil {
		log.Fatal(err)
	}
	aesGCM, err := cipher.NewGCM(aesBlock)
	if err != nil {
		log.Fatal(err)
	}
	nonce := make([]byte, aesGCM.NonceSize())
	_, err = rand.Read(nonce)
	if err != nil {
		log.Fatal(err)
	}
	ciphertext := aesGCM.Seal(nil, nonce, signingInput, nil)

	t.encryptedKey = encryptedKey
	t.iv = nonce
	t.cipherText = ciphertext
	t.authTag = []byte("")

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
