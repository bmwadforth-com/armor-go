package crypto

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
)

// DecodeRsaPublicKey decodes an RSA public key from its PEM-encoded representation.
//
// Parameters:
// - publicKeyPEM: A byte slice containing the PEM-encoded RSA public key.
//
// Returns:
//   - A pointer to an `rsa.PublicKey` structure representing the decoded public key.
//   - An error if there was any issue during the decoding process,
//     such as failure to parse the PEM block or invalid public key format.
//
// This function performs the following steps:
//  1. Decodes the PEM block from the input byte slice using `pem.Decode`.
//  2. Checks if a valid PEM block was found. If not, it returns an error.
//  3. Parses the public key from the decoded PEM block using `x509.ParsePKIXPublicKey`.
//  4. Asserts that the parsed key is of type `*rsa.PublicKey`.
//  5. Returns the extracted RSA public key and a nil error if successful,
//     or a nil key and the corresponding error if there was an issue.
func DecodeRsaPublicKey(publicKeyPEM []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(publicKeyPEM)
	if block == nil {
		return nil, errors.New("failed to parse PEM block containing the public key")
	}

	publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	rsaPublicKey := publicKey.(*rsa.PublicKey)
	return rsaPublicKey, nil
}

// DecodeRsaPrivateKey decodes an RSA private key from its PEM-encoded representation.
//
// Parameters:
//   - privateKeyPEM: A byte slice containing the PEM-encoded RSA private key.
//
// Returns:
//   - A pointer to an `rsa.PrivateKey` structure representing the decoded private key.
//   - An error if there was any issue during the decoding process, such as failure to
//     parse the PEM block or invalid private key format.
//
// This function performs the following steps:
//  1. Decodes the PEM block from the input byte slice using `pem.Decode`.
//  2. Checks if a valid PEM block was found. If not, it returns an error.
//  3. Parses the private key from the decoded PEM block using `x509.ParsePKCS8PrivateKey`.
//  4. Asserts that the parsed key is of type `*rsa.PrivateKey`.
//  5. Returns the extracted RSA private key and a nil error if successful, or a nil key
//     and the corresponding error if there was an issue.
func DecodeRsaPrivateKey(privateKeyPEM []byte) (*rsa.PrivateKey, error) {
	pemBlock, _ := pem.Decode(privateKeyPEM)
	if pemBlock == nil {
		return nil, fmt.Errorf("failed to parse PEM block containing the private key")
	}
	privateKey, err := x509.ParsePKCS8PrivateKey(pemBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}
	return privateKey.(*rsa.PrivateKey), nil
}
