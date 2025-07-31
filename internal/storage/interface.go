// Package storage provides interfaces and types for key-value storage operations.
// This file defines the Store interface and related types for storage implementations.
package storage

import (
	"context"
	"errors"
	"time"
)

var (
	// ErrKeyNotFound indicates that the requested key does not exist in the store.
	ErrKeyNotFound = errors.New("key not found")
	// ErrInvalidType indicates that the storage type is not recognized.
	ErrInvalidType = errors.New("invalid storage type")
	// ErrEntrySizeExceeded indicates that the cache entry exceeds the maximum allowed size.
	ErrEntrySizeExceeded = errors.New("cache entry size exceeds maximum allowed")
	// ErrPolicyCacheDisabled indicates that policy caching is disabled.
	ErrPolicyCacheDisabled = errors.New("policy cache is disabled")
)

// PolicyCacheEntry represents a cached policy evaluation result
type PolicyCacheEntry struct {
	Result    interface{} `json:"result"`
	CachedAt  time.Time   `json:"cached_at"`
	ExpiresAt time.Time   `json:"expires_at"`
	Size      int64       `json:"size"` // Size in bytes for monitoring
}

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

	// Ping checks the connection to the storage service.
	Ping(ctx context.Context) (string, error)

	// Close closes the storage connection.
	Close() error

	// Policy Cache Methods

	// StoreCachedPolicyResults caches policy evaluation results with size validation
	// Returns ErrEntrySizeExceeded if the entry exceeds configured size limits
	// Returns ErrPolicyCacheDisabled if policy caching is disabled
	StoreCachedPolicyResults(
		ctx context.Context,
		key string,
		result interface{},
		ttl time.Duration,
		maxSize int64,
	) error

	// GetCachedPolicyResults retrieves cached policy evaluation results
	// Returns ErrKeyNotFound if the cache entry doesn't exist or has expired
	// Returns ErrPolicyCacheDisabled if policy caching is disabled
	GetCachedPolicyResults(ctx context.Context, key string) (*PolicyCacheEntry, error)
}

// StoreType defines the type of storage being used.
// It can be "memory", "valkey", or any other custom storage type.
type StoreType string

const (
	// StoreTypeMemory represents an in-memory storage implementation.
	StoreTypeMemory StoreType = "memory"
	// StoreTypeValkey represents a Valkey-based storage implementation.
	StoreTypeValkey StoreType = "valkey"
)
