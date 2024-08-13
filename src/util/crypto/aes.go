package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
)

func EncryptAESGCM(cek, plaintext, aad []byte) (ciphertext, nonce, authTag []byte, err error) {
	aesBlock, err := aes.NewCipher(cek)
	if err != nil {
		return nil, nil, nil, err
	}
	aesGCM, err := cipher.NewGCM(aesBlock)
	if err != nil {
		return nil, nil, nil, err
	}
	nonce = make([]byte, aesGCM.NonceSize())
	_, err = rand.Read(nonce)
	if err != nil {
		return nil, nil, nil, err
	}

	ciphertextWithTag := aesGCM.Seal(nil, nonce, plaintext, aad)
	tagSize := aesGCM.Overhead()
	ciphertext = ciphertextWithTag[:len(ciphertextWithTag)-tagSize]
	authTag = ciphertextWithTag[len(ciphertextWithTag)-tagSize:]

	return ciphertext, nonce, authTag, nil
}
