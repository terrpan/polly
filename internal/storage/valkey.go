package storage

import (
	"context"
	"encoding/json"
	"time"

	"github.com/terrpan/polly/internal/config"
	"github.com/valkey-io/valkey-go"
)

// ValkeyStore implements Store interface using Valkey storage.
type ValkeyStore struct {
	client valkey.Client
}

func NewValkeyStore(cfg config.ValkeyConfig) (*ValkeyStore, error) {
	client, err := valkey.NewClient(valkey.ClientOption{
		InitAddress: []string{cfg.Address},
		Username:    cfg.Username,
		Password:    cfg.Password,
		SelectDB:    cfg.DB,
	})
	if err != nil {
		return nil, err
	}

	return &ValkeyStore{client: client}, nil
}

// Implement Store interface methods
func (v *ValkeyStore) Set(ctx context.Context, key string, value interface{}, expiration time.Duration) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}

	cmd := v.client.B().Set().Key(key).Value(string(data))
	if expiration > 0 {
		return v.client.Do(ctx, cmd.Ex(expiration).Build()).Error()
	}

	return v.client.Do(ctx, cmd.Build()).Error()
}

// Get retrieves the value for a given key.
func (v *ValkeyStore) Get(ctx context.Context, key string) (interface{}, error) {
	result := v.client.Do(ctx, v.client.B().Get().Key(key).Build())
	if result.Error() != nil {
		if valkey.IsValkeyNil(result.Error()) {
			return nil, ErrKeyNotFound
		}
		return nil, result.Error()
	}

	data, err := result.ToString()
	if err != nil {
		return nil, err
	}

	var value interface{}
	if err := json.Unmarshal([]byte(data), &value); err != nil {
		return nil, err
	}

	return value, nil
}

// Delete removes a key-value pair.
func (v *ValkeyStore) Delete(ctx context.Context, key string) error {
	return v.client.Do(ctx, v.client.B().Del().Key(key).Build()).Error()
}

// Exists checks if a key exists in the store.
func (v *ValkeyStore) Exists(ctx context.Context, key string) (bool, error) {
	result := v.client.Do(ctx, v.client.B().Exists().Key(key).Build())
	if result.Error() != nil {
		if valkey.IsValkeyNil(result.Error()) {
			return false, ErrKeyNotFound
		}
		return false, result.Error()
	}

	count, err := result.ToInt64()
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

// Close closes the Valkey client connection.
func (v *ValkeyStore) Close() error {
	v.client.Close()
	return nil
}
