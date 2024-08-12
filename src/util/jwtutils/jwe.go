package jwt

import "errors"

type JweToken struct {
	Header
	EncryptedKey         []byte
	InitializationVector []byte
	Ciphertext           []byte
	AuthenticationTag    []byte
}

func newJweToken(alg AlgorithmType, claims ClaimSet, key []byte) (*JweToken, error) {
	return nil, errors.New("jwe not implemented")
}

func (t *JweToken) encode() ([]byte, error) {
	return nil, errors.New("jwe encode not implemented")
}

func (t *JweToken) decode(parts []string) error {
	return errors.New("jwe decode not implemented")
}

func (t *JweToken) validate() (bool, error) {
	return false, errors.New("jwe validate not implemented")
}
