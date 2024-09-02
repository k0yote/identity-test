package handler

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/newlo/identity/internal/auth"
)

type ErrorResponse struct {
	Code    string `json:"error_code"`
	Message string `json:"error_message"`
}

func GenericAuthHandler(authService *auth.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			AuthType    string            `json:"auth_type"`
			Credentials map[string]string `json:"credentials"`
		}

		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			log.Printf("Error decoding request body: %v", err)
			sendErrorResponse(w, "invalid_request", "Invalid request body", http.StatusBadRequest)
			return
		}

		user, err := authService.Authenticate(req.AuthType, req.Credentials)
		if err != nil {
			log.Printf("Authentication failed: %v", err)
			sendErrorResponse(w, "authentication_failed", "Authentication failed", http.StatusUnauthorized)
			return
		}

		accessToken, idToken, err := authService.GenerateTokens(user)
		if err != nil {
			log.Printf("Failed to generate tokens: %v", err)
			sendErrorResponse(w, "token_generation_failed", "Failed to generate tokens", http.StatusInternalServerError)
			return
		}

		response := map[string]string{
			"access_token": accessToken,
			"id_token":     idToken,
			"token_type":   "Bearer",
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}
}

// You can now use this generic handler for X and Discord
func XAuthHandler(authService *auth.Service) http.HandlerFunc {
	return GenericAuthHandler(authService)
}

func DiscordAuthHandler(authService *auth.Service) http.HandlerFunc {
	return GenericAuthHandler(authService)
}

func Iden3AuthHandler(authService *auth.Service) http.HandlerFunc {
	return GenericAuthHandler(authService)
}

func EVMAuthHandler(authService *auth.Service) http.HandlerFunc {
	return GenericAuthHandler(authService)
}

func TokenHandler(service *auth.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		err := r.ParseForm()
		if err != nil {
			http.Error(w, "Failed to parse form data", http.StatusBadRequest)
			return
		}

		grantType := r.Form.Get("grant_type")
		if grantType != "authorization_code" {
			http.Error(w, "Unsupported grant type", http.StatusBadRequest)
			return
		}

		code := r.Form.Get("code")
		clientID := r.Form.Get("client_id")
		clientSecret := r.Form.Get("client_secret")

		// Validate client credentials and authorization code
		user, err := service.ValidateAuthorizationCode(code, clientID, clientSecret)
		if err != nil {
			http.Error(w, "Invalid authorization code or client credentials", http.StatusUnauthorized)
			return
		}

		accessToken, err := service.GenerateAccessToken(user)
		if err != nil {
			http.Error(w, "Failed to generate access token", http.StatusInternalServerError)
			return
		}

		idToken, err := service.GenerateIDToken(user)
		if err != nil {
			http.Error(w, "Failed to generate ID token", http.StatusInternalServerError)
			return
		}

		response := map[string]interface{}{
			"access_token": accessToken,
			"token_type":   "Bearer",
			"id_token":     idToken,
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}
}

func UserInfoHandler(service *auth.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
			http.Error(w, "Missing or invalid Authorization header", http.StatusUnauthorized)
			return
		}

		token := strings.TrimPrefix(authHeader, "Bearer ")
		claims, err := service.ValidateToken(token)
		if err != nil {
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}

		userInfo := map[string]interface{}{
			"sub":   claims["sub"],
			"name":  claims["name"],
			"email": claims["email"],
			// Add other claims as needed
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(userInfo)
	}
}

func AuthHandler(service *auth.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Parse the authorization request parameters
		err := r.ParseForm()
		if err != nil {
			http.Error(w, "Failed to parse form data", http.StatusBadRequest)
			return
		}

		// After successful authentication:
		clientID := r.Form.Get("client_id")
		redirectURI := r.Form.Get("redirect_uri")
		responseType := r.Form.Get("response_type")
		scope := r.Form.Get("scope")
		state := r.Form.Get("state")

		// Validate the request parameters
		if clientID == "" || redirectURI == "" || responseType != "code" {
			http.Error(w, "Invalid request parameters", http.StatusBadRequest)
			return
		}

		// Validate the client and redirect URI
		if !service.ValidateClient(clientID, redirectURI) {
			http.Error(w, "Invalid client or redirect URI", http.StatusBadRequest)
			return
		}

		// Check if the user is already authenticated (e.g., via session cookie)
		user, err := service.GetAuthenticatedUser(r)
		if err != nil {
			// User is not authenticated, initiate the authentication process
			authType := r.Form.Get("auth_type") // The client should specify the desired auth type
			switch authType {
			case "iden3", "evm", "x", "discord":
				// Redirect to the specific authentication page or initiate the auth process
				authURL := fmt.Sprintf("/auth/%s?client_id=%s&redirect_uri=%s&scope=%s&state=%s",
					authType, clientID, redirectURI, scope, state)
				http.Redirect(w, r, authURL, http.StatusFound)
				return
			default:
				http.Error(w, "Unsupported authentication type", http.StatusBadRequest)
				return
			}
		}

		code, err := service.CreateAuthorizationCode(clientID, user.ID, redirectURI, scope)
		if err != nil {
			http.Error(w, "Failed to create authorization code", http.StatusInternalServerError)
			return
		}

		// Redirect with the authorization code
		redirectURL := fmt.Sprintf("%s?code=%s&state=%s", redirectURI, code, r.Form.Get("state"))
		http.Redirect(w, r, redirectURL, http.StatusFound)
	}
}

// func Iden3AuthHandler(service *auth.Service) http.HandlerFunc {
// 	return func(w http.ResponseWriter, r *http.Request) {
// 		// Implement Iden3-specific authentication logic
// 		// This might involve verifying a proof or signature

// 		did := r.Form.Get("did")
// 		proof := r.Form.Get("proof")

// 		user, err := service.AuthenticateWithIden3(did, []byte(proof))
// 		if err != nil {
// 			http.Error(w, "Authentication failed", http.StatusUnauthorized)
// 			return
// 		}

// 		// Set session or token to maintain authenticated state
// 		service.SetAuthenticatedUser(r, w, user)

// 		// Redirect back to the main auth handler
// 		http.Redirect(w, r, "/auth"+r.URL.RawQuery, http.StatusFound)
// 	}
// }

// func EVMAuthHandler(service *auth.Service) http.HandlerFunc {
// 	return func(w http.ResponseWriter, r *http.Request) {
// 		// Implement EVM wallet authentication logic
// 		// This might involve verifying a signed message

// 		address := r.Form.Get("address")
// 		signature := r.Form.Get("signature")
// 		message := r.Form.Get("message")

// 		user, err := service.AuthenticateWithEVMWallet(address, signature, message)
// 		if err != nil {
// 			http.Error(w, "Authentication failed", http.StatusUnauthorized)
// 			return
// 		}

// 		service.SetAuthenticatedUser(r, w, user)
// 		http.Redirect(w, r, "/auth"+r.URL.RawQuery, http.StatusFound)
// 	}
// }

// // XAuthHandler handles authentication requests for X (Twitter)
// func XAuthHandler(service *auth.Service) http.HandlerFunc {
// 	return func(w http.ResponseWriter, r *http.Request) {
// 		var req struct {
// 			XUsername string `json:"x_username"`
// 			XToken    string `json:"x_token"`
// 		}

// 		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
// 			http.Error(w, "Invalid request body", http.StatusBadRequest)
// 			return
// 		}

// 		user, err := service.AuthenticateWithX(req.XUsername, req.XToken)
// 		if err != nil {
// 			http.Error(w, "Authentication failed: "+err.Error(), http.StatusUnauthorized)
// 			return
// 		}

// 		// Generate tokens (access token and ID token) for the authenticated user
// 		accessToken, idToken, err := service.GenerateTokens(user)
// 		if err != nil {
// 			http.Error(w, "Failed to generate tokens", http.StatusInternalServerError)
// 			return
// 		}

// 		response := map[string]string{
// 			"access_token": accessToken,
// 			"id_token":     idToken,
// 			"token_type":   "Bearer",
// 		}

// 		w.Header().Set("Content-Type", "application/json")
// 		json.NewEncoder(w).Encode(response)
// 	}
// }

// // DiscordAuthHandler handles authentication requests for Discord
// func DiscordAuthHandler(service *auth.Service) http.HandlerFunc {
// 	return func(w http.ResponseWriter, r *http.Request) {
// 		var req struct {
// 			DiscordID    string `json:"discord_id"`
// 			DiscordToken string `json:"discord_token"`
// 		}

// 		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
// 			http.Error(w, "Invalid request body", http.StatusBadRequest)
// 			return
// 		}

// 		user, err := service.AuthenticateWithDiscord(req.DiscordID, req.DiscordToken)
// 		if err != nil {
// 			http.Error(w, "Authentication failed: "+err.Error(), http.StatusUnauthorized)
// 			return
// 		}

// 		// Generate tokens (access token and ID token) for the authenticated user
// 		accessToken, idToken, err := service.GenerateTokens(user)
// 		if err != nil {
// 			http.Error(w, "Failed to generate tokens", http.StatusInternalServerError)
// 			return
// 		}

// 		response := map[string]string{
// 			"access_token": accessToken,
// 			"id_token":     idToken,
// 			"token_type":   "Bearer",
// 		}

// 		w.Header().Set("Content-Type", "application/json")
// 		json.NewEncoder(w).Encode(response)
// 	}
// }

func sendErrorResponse(w http.ResponseWriter, code string, message string, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(ErrorResponse{
		Code:    code,
		Message: message,
	})
}
