package storage

import (
	"context"
	"errors"
	"time"
)

var (
	ErrKeyNotFound = errors.New("key not found")
	ErrInvalidType = errors.New("invalid storage type")
)

// Store defines the interface for kv storage operations.
type Store interface {
	// Set stores a key-value pair with an optional expiration time.
	Set(ctx context.Context, key string, value interface{}, expiration time.Duration) error

	// Get retrieves the value for a given key.
	Get(ctx context.Context, key string) (interface{}, error)

	// Delete removes a key-value pair.
	Delete(ctx context.Context, key string) error

	// Exists checks if a key exists in the store.
	Exists(ctx context.Context, key string) (bool, error)

	// Close closes the storage connection.
	Close() error
}

// StoreType defines the type of storage being used.
// It can be "memory", "valkey", or any other custom storage type.
type StoreType string

const (
	StoreTypeMemory StoreType = "memory"
	StoreTypeValkey StoreType = "valkey"
)
