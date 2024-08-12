package jws

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
	"github.com/bmwadforth-com/armor-go/src/util/jwt/common"
)

func getJwsValidateFunc(a common.AlgorithmType) ValidateFunc {
	switch a {
	case common.HS256:
		return validateHMAC256
	case common.RS256:
		return validateRSA256
	case common.None:
		return func(_ *Token) (bool, error) {
			return true, nil
		}
	}

	return nil
}

func validateHMAC256(t *Token) (bool, error) {
	copiedRawToken := make([]byte, len(t.Raw))
	copy(copiedRawToken, t.Raw)

	encodedBytes, err := t.Encode()
	if err != nil {
		return false, err
	}

	if !bytes.Equal(encodedBytes, copiedRawToken) {
		return false, errors.New("failed to validate token - bytes are not equal")
	}

	return true, nil
}

func validateRSA256(t *Token) (bool, error) {
	block, _ := pem.Decode(t.Key)
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return false, err
	}

	headerB64, _ := t.Header.ToBase64()
	payloadB64, _ := t.Payload.ToBase64()

	hashed := sha256.Sum256([]byte(fmt.Sprintf("%s.%s", headerB64, payloadB64)))

	decodedSignature, err := base64.RawURLEncoding.DecodeString(string(t.Signature.Raw))
	if err != nil {
		return false, err
	}

	err = rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA256, hashed[:], decodedSignature)
	if err != nil {
		return false, err
	}

	return true, nil
}
