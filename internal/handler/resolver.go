package handler

import (
	"encoding/json"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/newlo/identity/internal/service"
	"github.com/newlo/identity/pkg/models"
)

func ResolveHandler(resolverService *service.ResolverService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		did := vars["did"]

		if did == "" {
			http.Error(w, "DID is required", http.StatusBadRequest)
			return
		}

		didDocument, err := resolverService.ResolveDID(did)
		if err != nil {
			http.Error(w, "Failed to resolve DID: "+err.Error(), http.StatusInternalServerError)
			return
		}

		response := map[string]interface{}{
			models.JSONKeyContext: didDocument.Context,
			models.JSONKeyID:      didDocument.ID,
			"authentication":      didDocument.Authentication,
			"verificationMethod":  didDocument.VerificationMethod,
			"service":             didDocument.Service,
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}
}
