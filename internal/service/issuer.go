package service

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/newlo/identity/pkg/models"
)

type IssuerService struct {
	Issuer     string
	PrivateKey ed25519.PrivateKey
}

func NewIssuerService(issuerDID string, privateKeyPEM []byte) (*IssuerService, error) {
	privateKey, err := ParseEd25519PrivateKeyPEM(privateKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %v", err)
	}

	return &IssuerService{
		Issuer:     issuerDID,
		PrivateKey: privateKey,
	}, nil
}

func (s *IssuerService) IssueCredential(subject string, credType string, claims map[string]interface{}) (*models.Credential, error) {
	now := time.Now()
	id := fmt.Sprintf("urn:uuid:%s", GenerateUUID())

	credential := &models.Credential{
		ID:           id,
		Context:      []string{"https://www.w3.org/2018/credentials/v1"},
		Type:         []string{"VerifiableCredential", credType},
		Issuer:       "did:example:issuer", // Replace with actual issuer DID
		IssuanceDate: now,
		Subject:      subject,
		Claims:       claims,
		// Proof: models.Proof{
		// 	Type:               "Ed25519Signature2018",
		// 	Created:            now,
		// 	ProofPurpose:       "assertionMethod",
		// 	VerificationMethod: "did:example:issuer#key1", // Replace with actual verification method
		// 	Signature:          "placeholder_signature",   // Replace with actual signature
		// },
	}

	// Create the payload to be signed
	payload, err := createSigningPayload(credential)
	if err != nil {
		return nil, fmt.Errorf("failed to create signing payload: %v", err)
	}

	// Sign the payload
	signature := ed25519.Sign(s.PrivateKey, payload)

	// Create the proof
	credential.Proof = models.Proof{
		Type:               "Ed25519Signature2018",
		Created:            now,
		ProofPurpose:       "assertionMethod",
		VerificationMethod: fmt.Sprintf("%s#keys-1", s.Issuer),
		Signature:          base64.RawURLEncoding.EncodeToString(signature),
	}

	return credential, nil
}

func createSigningPayload(credential *models.Credential) ([]byte, error) {
	// Create a copy of the credential without the proof
	payloadCred := *credential
	payloadCred.Proof = models.Proof{}

	// Canonicalize the credential
	canonicalized, err := canonicalize(payloadCred)
	if err != nil {
		return nil, fmt.Errorf("failed to canonicalize credential: %v", err)
	}

	return []byte(canonicalized), nil
}

func canonicalize(v interface{}) (string, error) {
	// This is a simple JSON canonicalization.
	// For production use, consider using a proper JSON-LD canonicalization algorithm.
	canonicalized, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	return string(canonicalized), nil
}

// Helper functions

func ParseEd25519PrivateKeyPEM(pemBytes []byte) (ed25519.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("failed to parse PEM block containing the private key")
	}

	privateKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	ed25519Key, ok := privateKey.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("private key is not an Ed25519 key")
	}

	return ed25519Key, nil
}

func GenerateUUID() string {
	return uuid.New().String()
}
