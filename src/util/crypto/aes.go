package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
)

// EncryptAESGCM encrypts the given plaintext using AES in GCM mode.
//
// Parameters:
//   - cek: The Content Encryption Key (CEK) used for encryption.
//   - plaintext: The data to be encrypted.
//   - aad: Additional authenticated data (AAD) to be included in the encryption process but not encrypted itself.
//     This provides additional integrity protection.
//
// Returns:
// - ciphertext: The encrypted data.
// - nonce: The unique initialization vector (IV) used for this encryption.
// - authTag: The authentication tag generated during encryption, used for verifying data integrity and authenticity.
// - err: An error if any occurred during the encryption process.
//
// This function performs the following steps:
// 1. Creates a new AES cipher block using the provided CEK.
// 2. Creates a GCM cipher instance using the AES block.
// 3. Generates a random nonce of the appropriate size.
// 4. Encrypts the plaintext along with the AAD using the GCM cipher, producing ciphertext and an authentication tag.
// 5. Extracts the ciphertext and authentication tag from the combined output.
// 6. Returns the ciphertext, nonce, authentication tag, and any potential error.
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
