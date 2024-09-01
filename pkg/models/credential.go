package models

import "time"

type Credential struct {
	ID           string                 `json:"id"`
	Context      []string               `json:"@context"`
	Type         []string               `json:"type"`
	Issuer       string                 `json:"issuer"`
	IssuanceDate time.Time              `json:"issuanceDate"`
	Subject      string                 `json:"credentialSubject"`
	Claims       map[string]interface{} `json:"claims"`
	Proof        Proof                  `json:"proof"`
}

type Proof struct {
	Type               string    `json:"type"`
	Created            time.Time `json:"created"`
	ProofPurpose       string    `json:"proofPurpose"`
	VerificationMethod string    `json:"verificationMethod"`
	Signature          string    `json:"jws"`
}
