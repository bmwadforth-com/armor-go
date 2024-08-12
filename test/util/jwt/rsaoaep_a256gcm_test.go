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

func TestDecodeRSAOAEP_With_A256GCM(t *testing.T) {
	key, _ := os.ReadFile("./rsa_private_key.pem")
	tokenString := "eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00iLCJ0eXAiOiJKV1QifQ.P23TqJo5DMz290r4IJA93PMQYcF2hDeO7tu8C2yLNkrHCYWI1IkBzn4-0wl-gc3LKLxPk36c_SBTOw7PbUVS68gNWaAd8MQRJt30HnknttjNKMmk7gG__V9EQlRsYSrsqT5kRJAhvxMt9O6NomjUliFzKAuTCUWExDuDjpfsif6O6Sef_i-16hHncPUrQlzq2t3K-Wnrbau8nneTf0vx3lKKc_D6h3fYcJZ7N7dhO_8UwX38cEymzmrt8Bu8CZha98rG5UqgqzarDUKYyvpLOs-9QyFr3Gg3gW3d_iUGm_AwG29i0xYdx7xfclq5LThLy_J-afJwvskH2gKHR-hYWg.eTXrExHrq26NoRLH.pEu23G4BTtLrNlunj5kZV9iokOamfO2x1BG-nuc1yTQ1mhEC."

	_, err := jwt.Decode(tokenString, key)
	if err != nil {
		t.Fatal(err)
	}
}

func TestValidateRSAOAEP_With_A256GCM(t *testing.T) {
	key, _ := os.ReadFile("./rsa_private_key.pem")
	tokenString := "eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00iLCJ0eXAiOiJKV1QifQ.P23TqJo5DMz290r4IJA93PMQYcF2hDeO7tu8C2yLNkrHCYWI1IkBzn4-0wl-gc3LKLxPk36c_SBTOw7PbUVS68gNWaAd8MQRJt30HnknttjNKMmk7gG__V9EQlRsYSrsqT5kRJAhvxMt9O6NomjUliFzKAuTCUWExDuDjpfsif6O6Sef_i-16hHncPUrQlzq2t3K-Wnrbau8nneTf0vx3lKKc_D6h3fYcJZ7N7dhO_8UwX38cEymzmrt8Bu8CZha98rG5UqgqzarDUKYyvpLOs-9QyFr3Gg3gW3d_iUGm_AwG29i0xYdx7xfclq5LThLy_J-afJwvskH2gKHR-hYWg.eTXrExHrq26NoRLH.pEu23G4BTtLrNlunj5kZV9iokOamfO2x1BG-nuc1yTQ1mhEC."

	token, err := jwt.Decode(tokenString, key)
	if err != nil {
		t.Fatal(err)
	}

	_, err = jwt.Validate(token)
	if err != nil {
		t.Fatal(err)
	}
}
