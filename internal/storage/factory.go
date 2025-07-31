package storage

import (
	"fmt"

	"github.com/terrpan/polly/internal/config"
)

// NewStore creates a new store based on the provided configuration.
func NewStore(cfg config.StorageConfig) (Store, error) {
	switch cfg.Type {
	case string(StoreTypeMemory):
		return NewMemoryStore(), nil
	case string(StoreTypeValkey):
		store, err := NewValkeyStore(cfg.Valkey)
		if err != nil {
			return nil, fmt.Errorf("failed to create Valkey store: %w", err)
		}

		return store, nil
	default:
		return nil, fmt.Errorf("%w: unsupported storage type %s", ErrInvalidType, cfg.Type)
	}
}
