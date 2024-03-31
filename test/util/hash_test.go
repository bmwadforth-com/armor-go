package util_test

import (
	"github.com/bmwadforth/galaxy/src/util"
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
		result, _ := util.GenerateSha1Hash(tc.input)
		assert.Equal(t, tc.expected, result, "Incorrect SHA1 hash")
	}
}

func TestHashPassword(t *testing.T) {
	password := []byte("testpassword")

	_, err := util.HashPassword(password)
	require.NoError(t, err, "Hashing the password should not produce an error")
}

func TestPasswordHashMatch(t *testing.T) {
	password := []byte("testpassword")
	hashedPassword, _ := util.HashPassword(password)

	case1, _ := util.PasswordHashMatch(hashedPassword, password)
	case2, _ := util.PasswordHashMatch(hashedPassword, []byte("wrongpassword"))
	case3, _ := util.PasswordHashMatch([]byte("invalid"), password)
	// Success case
	assert.True(t, case1, "Passwords should match")

	// Failure case
	assert.False(t, case2, "Passwords shouldn't match")

	// Error case with invalid hashedPassword
	assert.False(t, case3, "PasswordHashMatch should fail with invalid input")
}
