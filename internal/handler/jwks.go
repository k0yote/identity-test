package handler

import (
	"encoding/json"
	"net/http"

	"github.com/newlo/identity/internal/auth"
)

func JWKSHandler(service *auth.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		jwks := service.GetJWKS()

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(jwks)
	}
}
