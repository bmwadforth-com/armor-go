package jwt

import (
	"fmt"
	"github.com/bmwadforth-com/armor-go/src/util/jwt"
	"github.com/bmwadforth-com/armor-go/src/util/jwt/common"
	"os"
	"testing"
)

func TestEncodeRSAOAEP_With_A256GCM(t *testing.T) {
	key, _ := os.ReadFile("./rsa_public_key.pem")
	claims := common.NewClaimSet()
	err := claims.Add(string(common.Audience), "developers")
	if err != nil {
		t.Fatal(err)
	}

	token, err := jwt.New(common.AlgorithmSuite{
		AlgorithmType:     common.RSA_OAEP,
		AuthAlgorithmType: common.A256GCM,
	}, claims, key)
	if err != nil {
		t.Fatal(err)
	}

	encodedBytes, err := jwt.Encode(token)
	if err != nil {
		t.Fatal(err)
	}

	fmt.Println(string(encodedBytes))
}
