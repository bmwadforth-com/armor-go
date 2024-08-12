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

	JweAuthAlgorithmSizeMap = map[AuthAlgorithmType]int{
		A256GCM: 32,
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

// TokenInstance represents an interface for working with tokens.
// TokenInstance will either be an instance of a JWE or JWS token.
type TokenInstance interface {
	// Encode generates a serialized representation of the token, typically in a compact format like JWE or JWT.
	// It returns the encoded token as a byte slice and any potential errors encountered during encoding.
	Encode() ([]byte, error)

	// Decode parses a serialized token (split into its parts) and populates the internal token structure.
	// It takes the token parts as input and returns an error if the decoding or parsing process fails.
	Decode(parts []string) error

	// Validate verifies the integrity and authenticity of the token, checking signatures, claims, and expiration if applicable.
	// It returns a boolean indicating whether the token is valid and any potential errors encountered during validation.
	Validate() (bool, error)
}
