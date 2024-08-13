package crypto

import (
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"golang.org/x/crypto/bcrypt"
)

func GenerateSha1Hash(data []byte) (string, error) {
	h := sha1.New()
	_, err := h.Write(data)
	if err != nil {
		return "", err
	}
	sha1Hash := hex.EncodeToString(h.Sum(nil))

	return sha1Hash, nil
}

func HashPassword(password []byte) ([]byte, error) {
	hashedPassword, err := bcrypt.GenerateFromPassword(password, bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}

	return hashedPassword, nil
}

func PasswordHashMatch(hashedPassword []byte, password []byte) (bool, error) {
	err := bcrypt.CompareHashAndPassword(hashedPassword, password)

	if err != nil {
		if errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
			return false, err
		} else {
			return false, err
		}
	}

	return true, nil
}