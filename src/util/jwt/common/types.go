package common

type TokenType string
type AlgorithmType string
type AuthAlgorithmType string
type AlgorithmSuite struct {
	AlgorithmType
	AuthAlgorithmType
}

const (
	JWS TokenType = "jws"
	JWE TokenType = "jwe"

	// JWS
	HS256 AlgorithmType = "HS256"
	RS256 AlgorithmType = "RS256"
	None  AlgorithmType = "none"

	// JWE
	RSA_OAEP AlgorithmType     = "RSA-OAEP"
	A256GCM  AuthAlgorithmType = "A256GCM"
)

var (
	// JWS
	JwsAlgorithmsMap = map[AlgorithmType]bool{
		HS256: true,
		RS256: true,
		None:  true,
	}

	// JWE
	JweAlgorithmsMap = map[AlgorithmType]bool{
		RSA_OAEP: true,
	}

	JweAuthAlgorithmsMap = map[AuthAlgorithmType]bool{
		A256GCM: true,
	}
)

type Header struct {
	Properties map[string]interface{}
	Raw        []byte
}

type Payload struct {
	ClaimSet
	Raw []byte
}

type Signature struct {
	Raw []byte
}

type Token struct {
	TokenType
	TokenInstance
	Claims map[string]interface{}
	Raw    []byte
}

type TokenInstance interface {
	Encode() ([]byte, error)
	Decode(parts []string) error
	Validate() (bool, error)
}
