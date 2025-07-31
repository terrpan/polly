package storage

import (
	"context"
	"sync"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
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
	tracer := otel.Tracer("polly/storage")

	_, span := tracer.Start(ctx, "storage.memory.set")
	defer span.End()

	span.SetAttributes(
		attribute.String("storage.type", "memory"),
		attribute.String("storage.key", key),
		attribute.String("ttl", expiration.String()),
	)

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
	tracer := otel.Tracer("polly/storage")

	_, span := tracer.Start(ctx, "storage.memory.get")
	defer span.End()

	span.SetAttributes(
		attribute.String("storage.type", "memory"),
		attribute.String("storage.key", key),
	)

	m.mutex.RLock()
	defer m.mutex.RUnlock()

	// Check if key has expired and clean up if so
	if m.cleanupExpiredKey(key) {
		span.SetAttributes(
			attribute.Bool("cache.hit", false),
			attribute.String("cache.miss_reason", "expired"),
		)

		return nil, ErrKeyNotFound
	}

	value, exists := m.data[key]
	if !exists {
		span.SetAttributes(
			attribute.Bool("cache.hit", false),
			attribute.String("cache.miss_reason", "not_found"),
		)

		return nil, ErrKeyNotFound
	}

	span.SetAttributes(attribute.Bool("cache.hit", true))

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

// StoreCachedPolicyResults caches policy evaluation results with size validation
func (m *MemoryStore) StoreCachedPolicyResults(
	ctx context.Context,
	key string,
	result interface{},
	ttl time.Duration,
	maxSize int64,
) error {
	tracer := otel.Tracer("polly/storage")

	_, span := tracer.Start(ctx, "storage.memory.store_policy_cache")
	defer span.End()

	// Estimate size for validation
	resultSize := m.estimateSize(result)
	span.SetAttributes(
		attribute.String("cache.key", key),
		attribute.Int64("cache.size_bytes", resultSize),
		attribute.Int64("cache.max_size_bytes", maxSize),
		attribute.String("cache.ttl", ttl.String()),
	)

	if maxSize > 0 && resultSize > maxSize {
		span.SetAttributes(attribute.Bool("cache.size_exceeded", true))
		return ErrEntrySizeExceeded
	}

	now := time.Now()
	entry := &PolicyCacheEntry{
		Result:    result,
		CachedAt:  now,
		ExpiresAt: now.Add(ttl),
		Size:      resultSize,
	}

	m.mutex.Lock()
	defer m.mutex.Unlock()

	m.data[key] = entry
	if ttl > 0 {
		m.expiry[key] = entry.ExpiresAt
	}

	span.SetAttributes(attribute.Bool("cache.stored", true))

	return nil
}

// GetCachedPolicyResults retrieves cached policy evaluation results
func (m *MemoryStore) GetCachedPolicyResults(
	ctx context.Context,
	key string,
) (*PolicyCacheEntry, error) {
	tracer := otel.Tracer("polly/storage")

	_, span := tracer.Start(ctx, "storage.memory.get_policy_cache")
	defer span.End()

	span.SetAttributes(attribute.String("cache.key", key))

	m.mutex.RLock()
	defer m.mutex.RUnlock()

	// Check if key has expired and clean up if so
	if m.cleanupExpiredKey(key) {
		span.SetAttributes(
			attribute.Bool("cache.hit", false),
			attribute.String("cache.miss_reason", "expired"),
		)

		return nil, ErrKeyNotFound
	}

	value, exists := m.data[key]
	if !exists {
		span.SetAttributes(
			attribute.Bool("cache.hit", false),
			attribute.String("cache.miss_reason", "not_found"),
		)

		return nil, ErrKeyNotFound
	}

	entry, ok := value.(*PolicyCacheEntry)
	if !ok {
		span.SetAttributes(
			attribute.Bool("cache.hit", false),
			attribute.String("cache.miss_reason", "invalid_type"),
		)

		return nil, ErrKeyNotFound
	}

	span.SetAttributes(
		attribute.Bool("cache.hit", true),
		attribute.Int64("cache.size_bytes", entry.Size),
		attribute.String("cache.cached_at", entry.CachedAt.Format(time.RFC3339)),
		attribute.String("cache.expires_at", entry.ExpiresAt.Format(time.RFC3339)),
	)

	return entry, nil
}

// estimateSize provides a rough estimate of object size in bytes
// This is a simplified implementation for size validation
func (m *MemoryStore) estimateSize(value interface{}) int64 {
	// For simplicity, we'll use a basic estimation
	// In a real implementation, you might want to use reflection
	// or serialization to get more accurate sizes
	switch v := value.(type) {
	case string:
		return int64(len(v))
	case []byte:
		return int64(len(v))
	case map[string]interface{}:
		// Rough estimate: assume average key+value size of 50 bytes
		return int64(len(v) * 50)
	default:
		// Default estimate for unknown types
		return 1024 // 1KB default
	}
}
