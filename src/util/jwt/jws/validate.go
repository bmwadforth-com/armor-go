package jws

import (
	"crypto"
	"crypto/hmac"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/bmwadforth-com/armor-go/src/util/jwt/common"
	"strings"
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
	parts := strings.Split(t.Raw, ".")
	if len(parts) != 3 {
		return false, errors.New("invalid token format")
	}
	existingHMAC, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return false, fmt.Errorf("invalid HMAC format: %v", err)
	}

	payload := strings.Join(parts[:2], ".")
	expectedHMAC, _ := signHMAC256(t, []byte(payload))

	if !hmac.Equal(existingHMAC, expectedHMAC) {
		return false, errors.New("token validation failed")
	}

	return true, nil
}

func validateRSA256(t *Token) (bool, error) {
	block, _ := pem.Decode(t.Key)
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return false, err
	}

	headerB64, _ := t.Header.Serialize()
	payloadB64, _ := t.Payload.Serialize()

	hashed := sha256.Sum256([]byte(fmt.Sprintf("%s.%s", headerB64, payloadB64)))

	decodedSignature, err := base64.RawURLEncoding.DecodeString(t.Signature.Metadata.Base64)
	if err != nil {
		return false, err
	}

	err = rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA256, hashed[:], decodedSignature)
	if err != nil {
		return false, err
	}

	return true, nil
}
