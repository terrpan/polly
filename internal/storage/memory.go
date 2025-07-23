package storage

import (
	"context"
	"sync"
	"time"
)

// MemoryStore implements Store interface using in-memory storage
type MemoryStore struct {
	data   map[string]interface{}
	expiry map[string]time.Time
	mutex  sync.RWMutex
}

// NewMemoryStore creates a new MemoryStore instance
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		data:   make(map[string]interface{}),
		expiry: make(map[string]time.Time),
	}
}

// cleanupExpiredKey checks if a key has expired and removes it if so.
// Returns true if the key was expired and cleaned up, false otherwise.
// This method assumes the caller already holds the appropriate lock.
func (m *MemoryStore) cleanupExpiredKey(key string) bool {
	if expiry, exists := m.expiry[key]; exists && time.Now().After(expiry) {
		delete(m.data, key)
		delete(m.expiry, key)
		return true
	}
	return false
}

// Set stores a key-value pair with expiration time.
func (m *MemoryStore) Set(
	ctx context.Context,
	key string,
	value interface{},
	expiration time.Duration,
) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	m.data[key] = value
	if expiration > 0 {
		m.expiry[key] = time.Now().Add(expiration)
	} else {
		delete(m.expiry, key) // Remove expiration if no duration specified
	}
	return nil
}

// Get retrieves the value for a given key.
func (m *MemoryStore) Get(ctx context.Context, key string) (interface{}, error) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	// Check if key has expired and clean up if so
	if m.cleanupExpiredKey(key) {
		return nil, ErrKeyNotFound
	}

	value, exists := m.data[key]
	if !exists {
		return nil, ErrKeyNotFound
	}

	return value, nil
}

// Delete removes a key-value pair. Does not error if key doesn't exist.
func (m *MemoryStore) Delete(ctx context.Context, key string) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	delete(m.data, key)
	delete(m.expiry, key)

	return nil
}

// Exists checks if a key exists in the store and if it has expired.
func (m *MemoryStore) Exists(ctx context.Context, key string) (bool, error) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	// Check if key has expired and clean up if so
	if m.cleanupExpiredKey(key) {
		return false, nil
	}

	_, exists := m.data[key]
	return exists, nil
}

// Ping checks the connection to the storage service.
// For memory store, this always returns success since it's local.
func (m *MemoryStore) Ping(ctx context.Context) (string, error) {
	return "pong", nil
}

// Close closes the storage connection.
func (m *MemoryStore) Close() error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	m.data = make(map[string]interface{})
	m.expiry = make(map[string]time.Time)

	return nil
}
