package jws

import (
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"github.com/bmwadforth-com/armor-go/src/util/jwt/common"
)

func getJwsSignFunc(a common.AlgorithmType) SignFunc {
	switch a {
	case common.HS256:
		return signHMAC256
	case common.RS256:
		return signRSA256
	case common.None:
		return func(_ *Token, _ []byte) ([]byte, error) {
			return nil, nil
		}
	}

	return nil
}

func signHMAC256(t *Token, signingInput []byte) ([]byte, error) {
	mac := hmac.New(sha256.New, t.Key)
	mac.Write(signingInput)
	signedBytes := mac.Sum(nil)

	return signedBytes, nil
}

func signRSA256(t *Token, signingInput []byte) ([]byte, error) {
	block, _ := pem.Decode(t.Key)
	key, _ := x509.ParsePKCS1PrivateKey(block.Bytes)

	rng := rand.Reader
	hashed := sha256.Sum256(signingInput)

	signature, err := rsa.SignPKCS1v15(rng, key, crypto.SHA256, hashed[:])
	if err != nil {
		return nil, err
	}

	return signature, nil
}
