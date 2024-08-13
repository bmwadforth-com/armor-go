package jwt

import (
	"errors"
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

	token, err := jwt.new(common.AlgorithmSuite{
		AlgorithmType:     common.RSA_OAEP,
		AuthAlgorithmType: common.A256GCM,
	}, claims, key)
	if err != nil {
		t.Fatal(err)
	}

	_, err = jwt.encodeToken(token)
	if err != nil {
		t.Fatal(err)
	}
}

func TestDecodeRSAOAEP_With_A256GCM(t *testing.T) {
	key, _ := os.ReadFile("./rsa_private_key.pem")
	tokenString := "eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00iLCJ0eXAiOiJKV1QifQ.g5OOMStCuKtGUDzkk1Wc_Pk7Mz3CF1fDfB6U9_zuY0h52wbty3xJxCarb7HjR1ASeeLMlhKFT2FHdXJ8WgXvCpWGONdYdK7crb6wPbtnct4e2vWLUVKBiYUGb-9z_9n4Jf16vCljfSyoSz2Nov5G_ZLUp0wUDlvc37P2UAeD_iwGY2RyJ_fc7lcBYhAySHk_sxc0ibweGNMFvjjDwCAlUxvrk_bKL-uuIsAyeOaZm7c6BBJJt_oy_sz9r-BKbIjd9sSit3Msu18c6xDWDH-VooM41zJSf-zN_HNgfWXnKgpwt9Inv6bFIbq7A4Xa70zNRVLsIHI22Wr1D-WnZl5awQ.BKjknUJyZRBEAp-_.XclvzVgYoyrTWk8q5ThUvGVRJ7k.Tlza0oGupfUjyHxKD14G9Q"

	_, err := jwt.decodeToken(tokenString, key)
	if err != nil {
		t.Fatal(err)
	}
}

func TestValidateRSAOAEP_With_A256GCM(t *testing.T) {
	key, _ := os.ReadFile("./rsa_private_key.pem")
	tokenString := "eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00iLCJ0eXAiOiJKV1QifQ.g5OOMStCuKtGUDzkk1Wc_Pk7Mz3CF1fDfB6U9_zuY0h52wbty3xJxCarb7HjR1ASeeLMlhKFT2FHdXJ8WgXvCpWGONdYdK7crb6wPbtnct4e2vWLUVKBiYUGb-9z_9n4Jf16vCljfSyoSz2Nov5G_ZLUp0wUDlvc37P2UAeD_iwGY2RyJ_fc7lcBYhAySHk_sxc0ibweGNMFvjjDwCAlUxvrk_bKL-uuIsAyeOaZm7c6BBJJt_oy_sz9r-BKbIjd9sSit3Msu18c6xDWDH-VooM41zJSf-zN_HNgfWXnKgpwt9Inv6bFIbq7A4Xa70zNRVLsIHI22Wr1D-WnZl5awQ.BKjknUJyZRBEAp-_.XclvzVgYoyrTWk8q5ThUvGVRJ7k.Tlza0oGupfUjyHxKD14G9Q"

	token, err := jwt.decodeToken(tokenString, key)
	if err != nil {
		t.Fatal(err)
	}

	_, err = jwt.validateToken(token)
	if err != nil {
		t.Fatal(err)
	}

	if token.Claims[string(common.Audience)] != "developers" {
		t.Fatal(errors.New("claims not decoded correctly"))
	}
}
