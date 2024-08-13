package crypto

import (
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"golang.org/x/crypto/bcrypt"
)

// GenerateSha1Hash calculates the SHA-1 hash of the provided data.
//
// Parameters:
//   - data: The byte slice containing the data to be hashed.
//
// Returns:
//   - A string representing the hexadecimal encoding of the SHA-1 hash.
//   - An error if there's an issue writing the data to the hash function.
//
// This function creates a new SHA-1 hash instance, writes the input data to it,
// and then returns the hexadecimal representation of the resulting hash.
// If an error occurs during the write operation, it returns an empty string and the error.
func GenerateSha1Hash(data []byte) (string, error) {
	h := sha1.New()
	_, err := h.Write(data)
	if err != nil {
		return "", err
	}
	sha1Hash := hex.EncodeToString(h.Sum(nil))

	return sha1Hash, nil
}

// HashPassword securely hashes the given password using bcrypt.
//
// Parameters:
//   - password: A byte slice containing the plaintext password to be hashed.
//
// Returns:
//   - A byte slice containing the bcrypt hash of the password.
//   - An error if the hashing process fails.
//
// This function utilizes the bcrypt library to generate a secure hash of the provided password.
// It employs the `bcrypt.DefaultCost` for the cost parameter, which determines the computational
// complexity of the hashing process. A higher cost results in a stronger hash but also takes longer
// to compute.
// If an error occurs during the hashing process, it returns a nil slice and the corresponding error.
// Otherwise, it returns the hashed password and a nil error.
func HashPassword(password []byte) ([]byte, error) {
	hashedPassword, err := bcrypt.GenerateFromPassword(password, bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}

	return hashedPassword, nil
}

// PasswordHashMatch verifies if a plaintext password matches a given bcrypt hash.
//
// Parameters:
// - hashedPassword: A byte slice containing the bcrypt hash to be compared against.
// - password: A byte slice containing the plaintext password to be checked.
//
// Returns:
// - A boolean value indicating whether the password matches the hash (true) or not (false).
// - An error if there's an issue during the comparison process, or if the password doesn't match the hash.
//
// This function uses the `bcrypt.CompareHashAndPassword` function to securely compare the provided plaintext password
// against the given bcrypt hash. It handles potential errors that might occur during the comparison.
// If the password matches the hash, it returns 'true' and a nil error.
// If the password doesn't match or there's any other error, it returns 'false' along with the corresponding error.
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
