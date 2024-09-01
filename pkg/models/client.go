package models

type Client struct {
	ID           string   `json:"id"`
	Secret       string   `json:"secret"`
	RedirectURIs []string `json:"redirect_uris"`
	Name         string   `json:"name"`
	Description  string   `json:"description"`
	CreatedAt    int64    `json:"created_at"`
	UpdatedAt    int64    `json:"updated_at"`
}
