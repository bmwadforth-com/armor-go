package util_test

/*
func TestNewBearerToken(t *testing.T) {
	signingKey := "your-secret-signing-key"

	tokenBytes, _ := util.NewBearerToken(signingKey)
	assert.NotNil(t, tokenBytes, "Expected a non-nil token")

	tokenString := string(tokenBytes)
	isValid, _ := util.ValidateBearerToken(tokenString, signingKey)
	assert.True(t, isValid, "Expected the token to be valid")

	claims, _ := util.GetTokenClaims(tokenString, signingKey)
	assert.NotNil(t, claims, "Expected non-nil claims")

	assert.Equal(t, "web-template", claims["aud"])
	assert.Equal(t, "web-template", claims["sub"])
}

func TestValidateBearerToken_InvalidToken(t *testing.T) {
	signingKey := "your-secret-signing-key"
	invalidToken := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"

	isValid, _ := util.ValidateBearerToken(invalidToken, signingKey)
	assert.False(t, isValid, "Expected the token to be invalid")
}


func TestGetTokenClaims_InvalidToken(t *testing.T) {
	signingKey := "your-secret-signing-key"
	invalidToken := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"

	claims := crypto.GetTokenClaims(invalidToken, signingKey)
	assert.Nil(t, claims, "Expected nil claims for an invalid token")
}
*/
