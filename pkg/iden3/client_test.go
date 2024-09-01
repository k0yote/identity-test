package iden3

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestVerifyProof(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "/verify", r.URL.Path)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"valid": true}`))
	}))
	defer server.Close()

	client, err := NewClient(server.URL)
	assert.NoError(t, err)

	valid, err := client.VerifyProof("did:iden3:123", []byte("proof"))
	assert.NoError(t, err)
	assert.True(t, valid)
}
