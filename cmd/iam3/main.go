package main

import (
	"log"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/newlo/identity/internal/auth"
	"github.com/newlo/identity/internal/config"
	"github.com/newlo/identity/internal/handler"
	"github.com/newlo/identity/internal/store"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	userStore := store.NewInMemoryUserStore()
	clientStore := store.NewInMemoryClientStore()
	iden3Verifier := &auth.MockIden3Verifier{}

	authService, err := auth.NewService(clientStore, cfg, userStore, iden3Verifier)
	if err != nil {
		log.Fatalf("Failed to create auth service: %v", err)
	}

	r := mux.NewRouter()

	r.HandleFunc("/auth", handler.GenericAuthHandler(authService)).Methods("POST")
	// r.HandleFunc("/auth", handler.AuthHandler(authService)).Methods("POST")
	// r.HandleFunc("/token", handler.TokenHandler(authService)).Methods("POST")
	// r.HandleFunc("/userinfo", handler.UserInfoHandler(authService)).Methods("GET")
	// r.HandleFunc("/.well-known/jwks.json", handler.JWKSHandler(authService)).Methods("GET")
	// r.HandleFunc("/auth/evm", handler.GenericSocialAuthHandler(authService, "evm")).Methods("POST")
	// r.HandleFunc("/auth/x", handler.GenericSocialAuthHandler(authService, "x")).Methods("POST")
	// r.HandleFunc("/auth/discord", handler.GenericSocialAuthHandler(authService, "discord")).Methods("POST")
	// r.HandleFunc("/auth/iden3", handler.GenericSocialAuthHandler(authService, "iden3")).Methods("POST")

	log.Printf("Starting IAM3 server on %s", cfg.ServerAddress)
	log.Fatal(http.ListenAndServe(cfg.ServerAddress, r))
}
