package auth

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/golang-jwt/jwt"
	"github.com/google/uuid"
	"github.com/gorilla/sessions"
	"github.com/newlo/identity/internal/config"
	"github.com/newlo/identity/internal/store"
	"github.com/newlo/identity/pkg/iden3"
	"github.com/newlo/identity/pkg/models"
	"github.com/newlo/identity/pkg/utils"
)

type Service struct {
	cfg           *config.Config
	privateKey    ed25519.PrivateKey
	publicKey     ed25519.PublicKey
	userStore     store.UserStore
	iden3Client   *iden3.Client
	authCodes     map[string]AuthCodeInfo // stores active authorization codes
	clientStore   ClientStore
	sessionStore  sessions.Store
	iden3Verifier Iden3Verifier
}

type ClientStore interface {
	GetClient(clientID string) (*models.Client, error)
	CreateClient(client *models.Client) error
}

type Iden3Verifier interface {
	VerifyProof(did string, proof []byte) (bool, error)
}

type MockIden3Verifier struct{}

func (m *MockIden3Verifier) VerifyProof(did string, proof []byte) (bool, error) {
	// This is a placeholder. Replace with actual Iden3 proof verification logic
	return true, nil
}

type UserStore interface {
	GetUserByDID(did string) (*models.User, error)
	CreateUser(user *models.User) error
}

// AuthCodeInfo stores information about an issued authorization code
type AuthCodeInfo struct {
	ClientID    string
	UserID      string
	ExpiresAt   time.Time
	RedirectURI string
	Scope       string
}

func NewService(clientStore store.ClientStore, cfg *config.Config, userStore store.UserStore, iden3Verifier Iden3Verifier) (*Service, error) {
	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, fmt.Errorf("failed to generate Ed25519 key pair: %v", err)
	}

	iden3Client, err := iden3.NewClient(cfg.Iden3RootURL)
	if err != nil {
		return nil, fmt.Errorf("failed to create Iden3 client: %v", err)
	}

	return &Service{
		clientStore:   clientStore,
		cfg:           cfg,
		privateKey:    privateKey,
		publicKey:     publicKey,
		userStore:     userStore,
		iden3Client:   iden3Client,
		authCodes:     make(map[string]AuthCodeInfo),
		iden3Verifier: iden3Verifier,
	}, nil
}

func (s *Service) AuthenticateUser(authType string, credentials map[string]string) (*models.User, error) {
	switch authType {
	case "iden3":
		return s.authenticateWithIden3(credentials["did"], []byte(credentials["proof"]))
	case "evm":
		return s.authenticateWithEVMWallet(credentials["address"], credentials["signature"], credentials["message"])
	case "x":
		return s.authenticateWithX(credentials["username"], credentials["token"])
	case "discord":
		return s.authenticateWithDiscord(credentials["id"], credentials["token"])
	default:
		return nil, fmt.Errorf("unsupported authentication type: %s", authType)
	}
}

func (s *Service) authenticateWithIden3(did string, proof []byte) (*models.User, error) {
	valid, err := s.iden3Client.VerifyProof(did, proof)
	if err != nil {
		return nil, err
	}
	if !valid {
		return nil, errors.New("invalid Iden3 proof")
	}

	user, err := s.userStore.GetUserByDID(did)
	if err != nil {
		user = &models.User{DID: did}
		err = s.userStore.CreateUser(user)
		if err != nil {
			return nil, err
		}
	}

	return user, nil
}

// Implement authenticateWithEVMWallet, authenticateWithX, authenticateWithDiscord methods

func (s *Service) GenerateAccessToken(user *models.User) (string, error) {
	now := time.Now()
	claims := jwt.MapClaims{
		"iss": s.cfg.IssuerURL,
		"sub": user.ID,
		"aud": s.cfg.IssuerURL,
		"exp": now.Add(time.Hour).Unix(),
		"iat": now.Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	return token.SignedString(s.privateKey)
}

func (s *Service) GenerateIDToken(user *models.User) (string, error) {
	now := time.Now()
	claims := jwt.MapClaims{
		"iss":         s.cfg.IssuerURL,
		"sub":         user.ID,
		"aud":         s.cfg.IssuerURL,
		"exp":         now.Add(time.Hour).Unix(),
		"iat":         now.Unix(),
		"did":         user.DID,
		"evm_address": user.EVMAddress,
		"x_username":  user.XUsername,
		"discord_id":  user.DiscordID,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	return token.SignedString(s.privateKey)
}

func (s *Service) ValidateToken(tokenString string) (jwt.MapClaims, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodEd25519); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return s.publicKey, nil
	})

	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		return claims, nil
	}

	return nil, errors.New("invalid token")
}

func (s *Service) GetJWKS() map[string]interface{} {
	return map[string]interface{}{
		"keys": []map[string]interface{}{
			{
				"kty": "OKP",
				"use": "sig",
				"alg": "EdDSA",
				"kid": "1",
				"crv": "Ed25519",
				"x":   base64.RawURLEncoding.EncodeToString(s.publicKey),
			},
		},
	}
}

func (s *Service) CreateAuthorizationCode(clientID, userID, redirectURI, scope string) (string, error) {
	code, err := utils.GenerateSecureRandomString(32) // Generate a 32-character code
	if err != nil {
		return "", err
	}

	s.authCodes[code] = AuthCodeInfo{
		ClientID:    clientID,
		UserID:      userID,
		ExpiresAt:   time.Now().Add(10 * time.Minute), // Authorization codes typically have a short lifespan
		RedirectURI: redirectURI,
		Scope:       scope,
	}
	return code, nil
}

func (s *Service) ValidateAuthorizationCode(code, clientID, clientSecret string) (*models.User, error) {
	codeInfo, exists := s.authCodes[code]
	if !exists {
		return nil, errors.New("invalid authorization code")
	}

	if codeInfo.ClientID != clientID {
		return nil, errors.New("authorization code was not issued to this client")
	}

	if time.Now().After(codeInfo.ExpiresAt) {
		delete(s.authCodes, code) // Remove expired code
		return nil, errors.New("authorization code has expired")
	}

	// Validate client secret (in a real scenario, this would be more secure)
	if !s.validateClientSecret(clientID, clientSecret) {
		return nil, errors.New("invalid client secret")
	}

	// Fetch the user associated with this code
	user, err := s.userStore.GetUser(codeInfo.UserID)
	if err != nil {
		return nil, err
	}

	// Remove the used authorization code
	delete(s.authCodes, code)

	// return &models.User{
	// 	ID:         "user123",
	// 	DID:        "did:iden3:123456789abcdefghi",
	// 	EVMAddress: "0x1234567890123456789012345678901234567890",
	// 	XUsername:  "johndoe",
	// 	DiscordID:  "123456789",
	// }, nil

	return user, nil
}

func (s *Service) validateClientSecret(clientID, clientSecret string) bool {
	// In a real implementation, you would securely check the client secret
	// This is a placeholder implementation
	return true // Always returning true for this example
}

func (s *Service) ValidateClient(clientID, redirectURI string) bool {
	client, err := s.clientStore.GetClient(clientID)
	if err != nil {
		return false
	}

	for _, uri := range client.RedirectURIs {
		if uri == redirectURI {
			return true
		}
	}

	return false
}

func (s *Service) GetAuthenticatedUser(r *http.Request) (*models.User, error) {
	session, err := s.sessionStore.Get(r, "auth-session")
	if err != nil {
		return nil, err
	}

	userID, ok := session.Values["user_id"].(string)
	if !ok {
		return nil, errors.New("user not authenticated")
	}

	// Fetch user from your user store
	user, err := s.userStore.GetUser(userID)
	if err != nil {
		return nil, err
	}

	return user, nil // Implement logic to retrieve the authenticated user from session/token
}

func (s *Service) SetAuthenticatedUser(r *http.Request, w http.ResponseWriter, user *models.User) {
	session, _ := s.sessionStore.Get(r, "auth-session")
	session.Values["user_id"] = user.ID
	session.Save(r, w) // Implement logic to set the authenticated user (e.g., create a session)
}

func (s *Service) AuthenticateWithIden3(did string, proof []byte) (*models.User, error) {
	// Parse the DID
	// Verify the proof
	valid, err := s.iden3Verifier.VerifyProof(did, proof)
	if err != nil {
		return nil, fmt.Errorf("error verifying Iden3 proof: %v", err)
	}

	if !valid {
		return nil, errors.New("invalid Iden3 proof")
	}

	// Check if user exists, if not create a new one
	user, err := s.userStore.GetUserByDID(did)
	if err != nil {
		// User doesn't exist, create a new one
		newUser := &models.User{
			ID:  generateUniqueID(),
			DID: did,
		}
		err = s.userStore.CreateUser(newUser)
		if err != nil {
			return nil, fmt.Errorf("error creating new user: %v", err)
		}
		return newUser, nil
	}
	// id, err := did.ParseDID(didStr)
	// if err != nil {
	// 	return nil, err
	// }

	// // Verify the proof
	// valid, err := s.iden3Verifier.VerifyProof(id.String(), proof)
	// if err != nil {
	// 	return nil, err
	// }

	// if !valid {
	// 	return nil, errors.New("invalid Iden3 proof")
	// }

	// // Check if user exists, if not create a new one
	// user, err := s.userStore.GetUserByDID(id.String())
	// if err != nil {
	// 	// User doesn't exist, create a new one
	// 	user = &models.User{
	// 		ID:  generateUniqueID(), // Implement this function
	// 		DID: id.String(),
	// 	}
	// 	err = s.userStore.CreateUser(user)
	// 	if err != nil {
	// 		return nil, err
	// 	}
	// }

	return user, nil // Implement Iden3 authentication logic
}

func (s *Service) AuthenticateWithEVMWallet(address, signature, message string) (*models.User, error) {
	// Verify EIP-191 signature
	sig := hexToBytes(signature)
	if len(sig) != 65 {
		return nil, errors.New("invalid signature length")
	}
	if sig[64] != 27 && sig[64] != 28 {
		return nil, errors.New("invalid recovery id")
	}
	sig[64] -= 27 // Transform yellow paper V from 27/28 to 0/1

	pubKeyECDSA, err := crypto.SigToPub(signHash([]byte(message)), sig)
	if err != nil {
		return nil, err
	}

	addr := crypto.PubkeyToAddress(*pubKeyECDSA)
	if !strings.EqualFold(addr.Hex(), address) {
		return nil, errors.New("address does not match recovered address")
	}

	// Check if user exists, if not create a new one
	user, err := s.userStore.GetUserByEVMAddress(address)
	if err != nil {
		// User doesn't exist, create a new one
		user = &models.User{
			ID:         generateUniqueID(), // Implement this function
			EVMAddress: address,
		}
		err = s.userStore.CreateUser(user)
		if err != nil {
			return nil, err
		}
	}

	return user, nil // Implement EVM wallet authentication logic
}

func (s *Service) CreateClient(name, description string, redirectURIs []string) (*models.Client, error) {
	clientID, err := utils.GenerateSecureRandomString(24)
	if err != nil {
		return nil, fmt.Errorf("failed to generate client ID: %v", err)
	}

	clientSecret, err := utils.GenerateSecureRandomString(32)
	if err != nil {
		return nil, fmt.Errorf("failed to generate client secret: %v", err)
	}

	client := &models.Client{
		ID:           clientID,
		Secret:       clientSecret,
		Name:         name,
		Description:  description,
		RedirectURIs: redirectURIs,
		CreatedAt:    time.Now().Unix(),
		UpdatedAt:    time.Now().Unix(),
	}

	err = s.clientStore.CreateClient(client)
	if err != nil {
		return nil, fmt.Errorf("failed to store client: %v", err)
	}

	return client, nil
}

func signHash(data []byte) []byte {
	msg := fmt.Sprintf("\x19Ethereum Signed Message:\n%d%s", len(data), data)
	return crypto.Keccak256([]byte(msg))
}

func hexToBytes(s string) []byte {
	if hasHexPrefix(s) {
		s = s[2:]
	}
	if len(s)%2 == 1 {
		s = "0" + s
	}
	return mustDecodeHex(s)
}

func hasHexPrefix(s string) bool {
	return len(s) >= 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X')
}

func mustDecodeHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func generateUniqueID() string {
	return uuid.New().String()
}

func (s *Service) authenticateWithEVMWallet(address, signature, message string) (*models.User, error) {
	// Verify EIP-191 signature
	sig := hexToBytes(signature)
	if len(sig) != 65 {
		return nil, errors.New("invalid signature length")
	}
	if sig[64] != 27 && sig[64] != 28 {
		return nil, errors.New("invalid recovery id")
	}
	sig[64] -= 27 // Transform yellow paper V from 27/28 to 0/1

	pubKeyECDSA, err := crypto.SigToPub(signHash([]byte(message)), sig)
	if err != nil {
		return nil, err
	}

	addr := crypto.PubkeyToAddress(*pubKeyECDSA)
	if !strings.EqualFold(addr.Hex(), address) {
		return nil, errors.New("address does not match recovered address")
	}

	// Check if user exists, if not create a new one
	user, err := s.userStore.GetUserByEVMAddress(address)
	if err != nil {
		// User doesn't exist, create a new one
		newUser := &models.User{
			ID:         generateUniqueID(),
			EVMAddress: address,
		}
		err = s.userStore.CreateUser(newUser)
		if err != nil {
			return nil, fmt.Errorf("failed to create user: %v", err)
		}
		return newUser, nil
	}

	return user, nil
}

func (s *Service) authenticateWithX(username, token string) (*models.User, error) {
	// Verify token with X (Twitter) API
	// This is a simplified example. In a real-world scenario, you would make an API call to X to verify the token.
	xUser, err := s.verifyXToken(token)
	if err != nil {
		return nil, fmt.Errorf("failed to verify X token: %v", err)
	}

	if xUser.Username != username {
		return nil, errors.New("X username mismatch")
	}

	// Check if user exists, if not create a new one
	user, err := s.userStore.GetUserByXUsername(username)
	if err != nil {
		// User doesn't exist, create a new one
		newUser := &models.User{
			ID:        generateUniqueID(),
			XUsername: username,
		}
		err = s.userStore.CreateUser(newUser)
		if err != nil {
			return nil, fmt.Errorf("failed to create user: %v", err)
		}
		return newUser, nil
	}

	return user, nil
}

func (s *Service) AuthenticateWithX(username, token string) (*models.User, error) {
	// Verify token with X (Twitter) API
	// This is a simplified example. In a real-world scenario, you would make an API call to X to verify the token.
	xUser, err := s.verifyXToken(token)
	if err != nil {
		return nil, fmt.Errorf("failed to verify X token: %v", err)
	}

	if xUser.Username != username {
		return nil, errors.New("X username mismatch")
	}

	// Check if user exists, if not create a new one
	user, err := s.userStore.GetUserByXUsername(username)
	if err != nil {
		// User doesn't exist, create a new one
		newUser := &models.User{
			ID:        generateUniqueID(),
			XUsername: username,
		}
		err = s.userStore.CreateUser(newUser)
		if err != nil {
			return nil, fmt.Errorf("failed to create user: %v", err)
		}
		return newUser, nil
	}

	return user, nil
}

func (s *Service) authenticateWithDiscord(discordID, token string) (*models.User, error) {
	// Verify token with Discord API
	// This is a simplified example. In a real-world scenario, you would make an API call to Discord to verify the token.
	discordUser, err := s.verifyDiscordToken(token)
	if err != nil {
		return nil, fmt.Errorf("failed to verify Discord token: %v", err)
	}

	if discordUser.ID != discordID {
		return nil, errors.New("Discord ID mismatch")
	}

	// Check if user exists, if not create a new one
	user, err := s.userStore.GetUserByDiscordID(discordID)
	if err != nil {
		// User doesn't exist, create a new one
		newUser := &models.User{
			ID:        generateUniqueID(),
			DiscordID: discordID,
		}
		err = s.userStore.CreateUser(newUser)
		if err != nil {
			return nil, fmt.Errorf("failed to create user: %v", err)
		}
		return newUser, nil
	}

	return user, nil
}

func (s *Service) AuthenticateWithDiscord(discordID, token string) (*models.User, error) {
	// Verify token with Discord API
	// This is a simplified example. In a real-world scenario, you would make an API call to Discord to verify the token.
	discordUser, err := s.verifyDiscordToken(token)
	if err != nil {
		return nil, fmt.Errorf("failed to verify Discord token: %v", err)
	}

	if discordUser.ID != discordID {
		return nil, errors.New("Discord ID mismatch")
	}

	// Check if user exists, if not create a new one
	user, err := s.userStore.GetUserByDiscordID(discordID)
	if err != nil {
		// User doesn't exist, create a new one
		newUser := &models.User{
			ID:        generateUniqueID(),
			DiscordID: discordID,
		}
		err = s.userStore.CreateUser(newUser)
		if err != nil {
			return nil, fmt.Errorf("failed to create user: %v", err)
		}
		return newUser, nil
	}

	return user, nil
}

type XUser struct {
	ID       string `json:"id"`
	Username string `json:"username"`
}

func (s *Service) verifyXToken(token string) (*XUser, error) {
	req, err := http.NewRequest("GET", "https://api.twitter.com/2/users/me", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Add("Authorization", "Bearer "+token)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("X API returned status: %d", resp.StatusCode)
	}

	var result struct {
		Data XUser `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	return &result.Data, nil
}

type DiscordUser struct {
	ID       string `json:"id"`
	Username string `json:"username"`
}

func (s *Service) verifyDiscordToken(token string) (*DiscordUser, error) {
	req, err := http.NewRequest("GET", "https://discord.com/api/users/@me", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Add("Authorization", "Bearer "+token)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Discord API returned status: %d", resp.StatusCode)
	}

	var user DiscordUser
	if err := json.NewDecoder(resp.Body).Decode(&user); err != nil {
		return nil, err
	}

	return &user, nil
}

func (s *Service) GenerateTokens(user *models.User) (accessToken, idToken string, err error) {
	// Generate access token
	accessToken, err = s.GenerateAccessToken(user)
	if err != nil {
		return "", "", err
	}

	// Generate ID token
	idToken, err = s.GenerateIDToken(user)
	if err != nil {
		return "", "", err
	}

	return accessToken, idToken, nil
}
