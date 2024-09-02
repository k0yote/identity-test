package handler

import (
	"encoding/json"
	"net/http"

	"github.com/newlo/identity/internal/service"
	"github.com/newlo/identity/pkg/models"
)

func IssueHandler(issuerService *service.IssuerService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Subject string                 `json:"subject"`
			Type    string                 `json:"type"`
			Claims  map[string]interface{} `json:"claims"`
		}

		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}

		credential, err := issuerService.IssueCredential(req.Subject, req.Type, req.Claims)
		if err != nil {
			http.Error(w, "Failed to issue credential: "+err.Error(), http.StatusInternalServerError)
			return
		}

		response := map[string]interface{}{
			models.JSONKeyID:      credential.ID,
			models.JSONKeyContext: credential.Context,
			models.JSONKeyType:    credential.Type,
			"issuer":              credential.Issuer,
			"issuanceDate":        credential.IssuanceDate,
			"credentialSubject":   credential.Subject,
			"claims":              credential.Claims,
			"proof":               credential.Proof,
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}
}
