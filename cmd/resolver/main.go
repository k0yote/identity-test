package main

import (
	"log"
	"net/http"

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

	r := mux.NewRouter()

	resolverService := service.NewResolverService()

	// Resolver route
	r.HandleFunc("/resolve/{did}", handler.ResolveHandler(resolverService)).Methods("GET")

	log.Printf("Starting Resolver server on %s", cfg.ResolverAddress)
	log.Fatal(http.ListenAndServe(cfg.ResolverAddress, r))
}
