package config

import (
	"encoding/json"
	"os"
)

type Config struct {
	ServerAddress   string `json:"server_address"`
	ResolverAddress string `json:"resolver_address"`
	IssuerAddress   string `json:"issuer_address"`
	IssuerURL       string `json:"issuer_url"`
	Iden3RootURL    string `json:"iden3_root_url"`
}

func Load() (*Config, error) {
	file, err := os.Open("config.json")
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var cfg Config
	if err := json.NewDecoder(file).Decode(&cfg); err != nil {
		return nil, err
	}

	return &cfg, nil
}
