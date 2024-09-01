package handler

import (
	"encoding/json"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/newlo/identity/internal/service"
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

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(didDocument)
	}
}
