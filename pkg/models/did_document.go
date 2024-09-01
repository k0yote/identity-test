package models

type DIDDocument struct {
	Context            interface{}          `json:"@context"`
	ID                 string               `json:"id"`
	Authentication     []interface{}        `json:"authentication,omitempty"`
	VerificationMethod []VerificationMethod `json:"verificationMethod,omitempty"`
	Service            []Service            `json:"service,omitempty"`
}

type VerificationMethod struct {
	ID           string `json:"id"`
	Type         string `json:"type"`
	Controller   string `json:"controller"`
	PublicKeyJwk JWK    `json:"publicKeyJwk,omitempty"`
}

type JWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y,omitempty"`
}

type Service struct {
	ID              string `json:"id"`
	Type            string `json:"type"`
	ServiceEndpoint string `json:"serviceEndpoint"`
}
