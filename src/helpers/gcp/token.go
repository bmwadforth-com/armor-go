package gcp

import (
	"context"
	"github.com/bmwadforth-com/armor-go/src/util"
	"google.golang.org/api/idtoken"
)

// GetIdentityToken retrieves an identity token from GCP.
// Read more about ID tokens here: https://cloud.google.com/docs/authentication/get-id-token
func GetIdentityToken(ctx context.Context, audience string) (string, error) {
	ts, err := idtoken.NewTokenSource(ctx, audience)
	if err != nil {
		util.LogError("failed to create token source: %v", err)
		return "", err
	}

	token, err := ts.Token()
	if err != nil {
		util.LogError("failed to get token: %v", err)
		return "", err
	}

	return token.AccessToken, nil
}
