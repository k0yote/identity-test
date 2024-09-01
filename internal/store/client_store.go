package store

import (
	"errors"
	"sync"

	"github.com/newlo/identity/pkg/models"
)

type ClientStore interface {
	GetClient(clientID string) (*models.Client, error)
	CreateClient(client *models.Client) error
	UpdateClient(client *models.Client) error
	DeleteClient(clientID string) error
}

type InMemoryClientStore struct {
	clients map[string]*models.Client
	mutex   sync.RWMutex
}

func NewInMemoryClientStore() *InMemoryClientStore {
	return &InMemoryClientStore{
		clients: make(map[string]*models.Client),
	}
}

func (s *InMemoryClientStore) GetClient(clientID string) (*models.Client, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	client, ok := s.clients[clientID]
	if !ok {
		return nil, errors.New("client not found")
	}
	return client, nil
}

func (s *InMemoryClientStore) CreateClient(client *models.Client) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if _, exists := s.clients[client.ID]; exists {
		return errors.New("client already exists")
	}

	s.clients[client.ID] = client
	return nil
}

func (s *InMemoryClientStore) UpdateClient(client *models.Client) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if _, exists := s.clients[client.ID]; !exists {
		return errors.New("client not found")
	}

	s.clients[client.ID] = client
	return nil
}

func (s *InMemoryClientStore) DeleteClient(clientID string) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if _, exists := s.clients[clientID]; !exists {
		return errors.New("client not found")
	}

	delete(s.clients, clientID)
	return nil
}
