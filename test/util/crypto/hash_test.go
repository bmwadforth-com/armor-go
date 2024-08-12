package crypto_test

import (
	"github.com/bmwadforth-com/armor-go/src/util/crypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestGenerateSha1Hash(t *testing.T) {
	testCases := []struct {
		input    []byte
		expected string
	}{
		{[]byte("hello, world"), "b7e23ec29af22b0b4e41da31e868d57226121c84"},
		{[]byte(""), "da39a3ee5e6b4b0d3255bfef95601890afd80709"},
	}

	for _, tc := range testCases {
		result, _ := crypto.GenerateSha1Hash(tc.input)
		assert.Equal(t, tc.expected, result, "Incorrect SHA1 hash")
	}
}

func TestHashPassword(t *testing.T) {
	password := []byte("testpassword")

	_, err := crypto.HashPassword(password)
	require.NoError(t, err, "Hashing the password should not produce an error")
}

func TestPasswordHashMatch(t *testing.T) {
	password := []byte("testpassword")
	hashedPassword, _ := crypto.HashPassword(password)

	case1, _ := crypto.PasswordHashMatch(hashedPassword, password)
	case2, _ := crypto.PasswordHashMatch(hashedPassword, []byte("wrongpassword"))
	case3, _ := crypto.PasswordHashMatch([]byte("invalid"), password)

	assert.True(t, case1, "Passwords should match")

	assert.False(t, case2, "Passwords shouldn't match")

	assert.False(t, case3, "PasswordHashMatch should fail with invalid input")
}
