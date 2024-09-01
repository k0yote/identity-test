package store

import (
	"errors"
	"strings"
	"sync"

	"github.com/newlo/identity/pkg/models"
)

type UserStore interface {
	GetUser(id string) (*models.User, error)
	GetUserByDID(did string) (*models.User, error)
	CreateUser(user *models.User) error
	GetUserByEVMAddress(address string) (*models.User, error)
	GetUserByXUsername(username string) (*models.User, error)
	GetUserByDiscordID(discordID string) (*models.User, error)
	UpdateUser(user *models.User) error
}

type InMemoryUserStore struct {
	users map[string]*models.User
	mutex sync.RWMutex
}

func NewInMemoryUserStore() *InMemoryUserStore {
	return &InMemoryUserStore{
		users: make(map[string]*models.User),
	}
}

func (s *InMemoryUserStore) GetUser(id string) (*models.User, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	user, ok := s.users[id]
	if !ok {
		return nil, errors.New("user not found")
	}
	return user, nil
}

func (s *InMemoryUserStore) GetUserByDID(did string) (*models.User, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	for _, user := range s.users {
		if user.DID == did {
			return user, nil
		}
	}

	return nil, errors.New("user not found")
}

func (s *InMemoryUserStore) GetUserByEVMAddress(address string) (*models.User, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	normalizedAddress := strings.ToLower(address)
	for _, user := range s.users {
		if strings.ToLower(user.EVMAddress) == normalizedAddress {
			return user, nil
		}
	}
	return nil, errors.New("user not found")
}

func (s *InMemoryUserStore) GetUserByDiscordID(discordID string) (*models.User, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	for _, user := range s.users {
		if user.DiscordID == discordID {
			return user, nil
		}
	}
	return nil, errors.New("user not found")
}

func (s *InMemoryUserStore) GetUserByXUsername(username string) (*models.User, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	normalizedUsername := strings.ToLower(username)
	for _, user := range s.users {
		if strings.ToLower(user.XUsername) == normalizedUsername {
			return user, nil
		}
	}
	return nil, errors.New("user not found")
}

func (s *InMemoryUserStore) CreateUser(user *models.User) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if _, exists := s.users[user.ID]; exists {
		return errors.New("user already exists")
	}

	s.users[user.ID] = user
	return nil
}

func (s *InMemoryUserStore) UpdateUser(user *models.User) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if _, exists := s.users[user.ID]; !exists {
		return errors.New("user not found")
	}
	s.users[user.ID] = user
	return nil
}
