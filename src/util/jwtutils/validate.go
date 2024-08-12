package jwt

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
)

type jwsValidateFunc func(t *JwsToken) (bool, error)

func getJwsValidateFunc(a AlgorithmType) jwsValidateFunc {
	switch a {
	case HS256:
		return validateHMAC256
	case RS256:
		return validateRSA256
	case None:
		return func(_ *JwsToken) (bool, error) {
			return true, nil
		}
	}

	return nil
}

func validateHMAC256(t *JwsToken) (bool, error) {
	copiedRawToken := make([]byte, len(t.raw))
	copy(copiedRawToken, t.raw)

	encodedBytes, err := t.encode()
	if err != nil {
		return false, err
	}

	if !bytes.Equal(encodedBytes, copiedRawToken) {
		return false, errors.New("failed to validate token - bytes are not equal")
	}

	return true, nil
}

func validateRSA256(t *JwsToken) (bool, error) {
	block, _ := pem.Decode(t.key)
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return false, err
	}

	headerB64, _ := t.Header.toBase64()
	payloadB64, _ := t.Payload.toBase64()

	hashed := sha256.Sum256([]byte(fmt.Sprintf("%s.%s", headerB64, payloadB64)))

	decodedSignature, err := base64.RawURLEncoding.DecodeString(string(t.Signature.raw))
	if err != nil {
		return false, err
	}

	err = rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA256, hashed[:], decodedSignature)
	if err != nil {
		return false, err
	}

	return true, nil
}
