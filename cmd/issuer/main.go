package main

import (
	"log"
	"net/http"
	"os"

	"github.com/gorilla/mux"
	"github.com/newlo/identity/internal/config"
	"github.com/newlo/identity/internal/handler"
	"github.com/newlo/identity/internal/service"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	privateKeyPEM, err := os.ReadFile("path/to/private_key.pem")
	if err != nil {
		log.Fatalf("Failed to read private key: %v", err)
	}

	r := mux.NewRouter()
	issuerService, err := service.NewIssuerService("did:example:issuer", privateKeyPEM)
	if err != nil {
		log.Fatalf("Failed to create issuer service: %v", err)
	}

	r.HandleFunc("/issue", handler.IssueHandler(issuerService)).Methods("POST")

	log.Printf("Starting Issuer server on %s", cfg.IssuerAddress)
	log.Fatal(http.ListenAndServe(cfg.IssuerAddress, r))
}
