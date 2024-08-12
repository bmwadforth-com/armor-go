package jwt

import (
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
)

type jwsSignFunc func(t *JwsToken, signingInput []byte) ([]byte, error)

func getJwsSignFunc(a AlgorithmType) jwsSignFunc {
	switch a {
	case HS256:
		return signHMAC256
	case RS256:
		return signRSA256
	case None:
		return func(_ *JwsToken, _ []byte) ([]byte, error) {
			return nil, nil
		}
	}

	return nil
}

func signHMAC256(t *JwsToken, signingInput []byte) ([]byte, error) {
	mac := hmac.New(sha256.New, t.key)
	mac.Write(signingInput)
	signedBytes := mac.Sum(nil)

	return signedBytes, nil
}

func signRSA256(t *JwsToken, signingInput []byte) ([]byte, error) {
	block, _ := pem.Decode(t.key)
	key, _ := x509.ParsePKCS1PrivateKey(block.Bytes)

	rng := rand.Reader
	hashed := sha256.Sum256(signingInput)

	signature, err := rsa.SignPKCS1v15(rng, key, crypto.SHA256, hashed[:])
	if err != nil {
		return nil, err
	}

	return signature, nil
}
