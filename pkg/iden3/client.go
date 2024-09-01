package iden3

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
)

type Client struct {
	rootURL string
}

func NewClient(rootURL string) (*Client, error) {
	return &Client{rootURL: rootURL}, nil
}

func (c *Client) VerifyProof(did string, proof []byte) (bool, error) {
	url := fmt.Sprintf("%s/verify", c.rootURL)

	reqBody, err := json.Marshal(map[string]interface{}{
		"did":   did,
		"proof": proof,
	})
	if err != nil {
		return false, err
	}

	resp, err := http.Post(url, "application/json", bytes.NewBuffer(reqBody))
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	var result struct {
		Valid bool `json:"valid"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return false, err
	}

	return result.Valid, nil
}
