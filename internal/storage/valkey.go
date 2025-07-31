package storage

import (
	"bytes"
	"compress/zlib"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"time"

	"github.com/valkey-io/valkey-go"
	"github.com/valkey-io/valkey-go/valkeyotel"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/terrpan/polly/internal/config"
)

// ValkeyStore implements Store interface using Valkey storage.
type ValkeyStore struct {
	client            valkey.Client
	tracer            trace.Tracer
	logger            *slog.Logger
	enableCompression bool
}

// applyCommonValkeyConfig applies common configuration settings to both Sentinel and standard client options
func applyCommonValkeyConfig(clientOpts *valkey.ClientOption, cfg config.ValkeyConfig) {
	clientOpts.Username = cfg.Username
	clientOpts.Password = cfg.Password
	clientOpts.SelectDB = cfg.DB
}

// NewValkeyStore creates a new ValkeyStore instance with the provided configuration.
func NewValkeyStore(cfg config.ValkeyConfig) (*ValkeyStore, error) {
	logger := slog.Default().With("component", "valkey_store")

	var clientOpts valkey.ClientOption

	if cfg.EnableSentinel {
		// Sentinel configuration
		clientOpts = valkey.ClientOption{
			InitAddress: cfg.SentinelAddrs,
			Sentinel: valkey.SentinelOption{
				MasterSet: cfg.SentinelMaster,
				Username:  cfg.SentinelUsername,
				Password:  cfg.SentinelPassword,
			},
		}
		logger.Info("Configuring Valkey with Sentinel",
			"master", cfg.SentinelMaster,
			"sentinels", len(cfg.SentinelAddrs))
	} else {
		// Standard configuration
		clientOpts = valkey.ClientOption{
			InitAddress: []string{cfg.Address},
		}
		logger.Info("Configuring Valkey with direct connection", "address", cfg.Address)
	}

	// Apply common configuration settings
	applyCommonValkeyConfig(&clientOpts, cfg)

	var (
		client valkey.Client
		err    error
	)

	// Create client with or without OpenTelemetry

	if cfg.EnableOTel && config.AppConfig != nil && config.AppConfig.OTLP.EnableOTLP {
		client, err = valkeyotel.NewClient(clientOpts)
		if err != nil {
			return nil, fmt.Errorf("failed to create Valkey client with OpenTelemetry: %w", err)
		}

		logger.Info("Valkey client created with OpenTelemetry support")
	} else {
		client, err = valkey.NewClient(clientOpts)
		if err != nil {
			return nil, fmt.Errorf("failed to create Valkey client: %w", err)
		}

		logger.Info("Valkey client created without OpenTelemetry")
	}

	store := &ValkeyStore{
		client:            client,
		enableCompression: cfg.EnableCompression,
		logger:            logger,
		tracer:            otel.Tracer("valkey-store"),
	}

	// Test the connection during initialization
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	if _, err := store.Ping(ctx); err != nil {
		if closeErr := store.Close(); closeErr != nil {
			logger.Error("failed to close Valkey client during cleanup", "error", closeErr)
		}

		return nil, fmt.Errorf("failed to connect to Valkey server: %w", err)
	}

	if cfg.EnableCompression {
		logger.Info("Valkey compression enabled")
	}

	return store, nil
}

// handleValkeyNilError is a helper function to handle Valkey nil errors consistently
func (v *ValkeyStore) handleValkeyNilError(
	err error,
	span trace.Span,
	logMessage string,
) (handled bool, resultErr error) {
	if valkey.IsValkeyNil(err) {
		span.SetAttributes(attribute.String("valkey.result", logMessage))
		return true, ErrKeyNotFound
	}

	if err != nil {
		span.RecordError(err)
		return true, err
	}

	return false, nil
}

// compress compresses data using zlib if compression is enabled
func (v *ValkeyStore) compress(ctx context.Context, data []byte) ([]byte, error) {
	_, span := v.tracer.Start(ctx, "valkey.compress",
		trace.WithAttributes(
			attribute.Int("data.original.size.bytes", len(data)),
			attribute.Bool("compression.enabled", v.enableCompression),
		),
	)
	defer span.End()

	if !v.enableCompression {
		span.SetAttributes(attribute.String("compression.status", "disabled"))
		return data, nil
	}

	// Don't compress small data (less than 100 bytes) as compression overhead is likely to increase size
	const compressionThreshold = 100
	if len(data) < compressionThreshold {
		span.SetAttributes(
			attribute.String("compression.status", "skipped_small_data"),
			attribute.Int("compression.threshold_bytes", compressionThreshold),
		)

		return data, nil
	}

	var buf bytes.Buffer

	writer := zlib.NewWriter(&buf)

	if _, err := writer.Write(data); err != nil {
		if closeErr := writer.Close(); closeErr != nil {
			span.RecordError(closeErr)
		}

		span.RecordError(err)

		return nil, fmt.Errorf("failed to write data: %w", err)
	}

	if err := writer.Close(); err != nil {
		span.RecordError(err)
		return nil, fmt.Errorf("failed to close compressor: %w", err)
	}

	compressed := buf.Bytes()

	// If compression actually made it larger, return original data
	if len(compressed) >= len(data) {
		span.SetAttributes(
			attribute.String("compression.status", "skipped_no_benefit"),
			attribute.Int("data.compressed.size.bytes", len(compressed)),
			attribute.Float64("compression.ratio", float64(len(compressed))/float64(len(data))),
		)

		return data, nil
	}

	span.SetAttributes(
		attribute.Int("data.compressed.size.bytes", len(compressed)),
		attribute.Float64("compression.ratio", float64(len(data))/float64(len(compressed))),
		attribute.String("compression.status", "completed"),
	)

	return compressed, nil
}

// decompress decompresses data using zlib if compression is enabled
func (v *ValkeyStore) decompress(ctx context.Context, data []byte) ([]byte, error) {
	_, span := v.tracer.Start(ctx, "valkey.decompress",
		trace.WithAttributes(
			attribute.Int("data.compressed.size.bytes", len(data)),
			attribute.Bool("compression.enabled", v.enableCompression),
		),
	)
	defer span.End()

	if !v.enableCompression {
		span.SetAttributes(attribute.String("compression.status", "disabled"))
		return data, nil
	}

	// Try to decompress; if it fails, assume data wasn't compressed
	reader, err := zlib.NewReader(bytes.NewReader(data))
	if err != nil {
		// Data might not be compressed (could be small data or no compression benefit)
		span.SetAttributes(
			attribute.String("compression.status", "not_compressed"),
			attribute.String("decompression.note", "data_appears_uncompressed"),
		)

		return data, nil
	}
	// defer reader.Close()
	defer func() {
		if closeErr := reader.Close(); closeErr != nil {
			span.RecordError(closeErr)
			v.logger.Debug("Failed to close decompressor", "error", closeErr)
		}
	}()

	decompressed, err := io.ReadAll(reader)
	if err != nil {
		// If decompression fails, return original data (might not have been compressed)
		span.SetAttributes(
			attribute.String("compression.status", "decompression_failed"),
			attribute.String("decompression.note", "returning_original_data"),
		)
		v.logger.Debug("Failed to decompress data, returning original", "error", err)

		return data, nil
	}

	span.SetAttributes(
		attribute.Int("data.decompressed.size.bytes", len(decompressed)),
		attribute.Float64("compression.ratio", float64(len(decompressed))/float64(len(data))),
		attribute.String("compression.status", "completed"),
	)

	return decompressed, nil
}

// Set stores a value with the given key and expiration.
func (v *ValkeyStore) Set(
	ctx context.Context,
	key string,
	value interface{},
	expiration time.Duration,
) error {
	ctx, span := v.tracer.Start(ctx, "valkey.set",
		trace.WithAttributes(
			attribute.String("valkey.key", key),
			attribute.String("valkey.operation", "set"),
			attribute.String("expiration", expiration.String()),
		),
	)
	defer span.End()

	data, err := json.Marshal(value)
	if err != nil {
		span.RecordError(err)
		return fmt.Errorf("failed to marshal value: %w", err)
	}

	span.SetAttributes(attribute.Int("data.marshaled.size.bytes", len(data)))

	// Compress the data if compression is enabled
	compressedData, err := v.compress(ctx, data)
	if err != nil {
		span.RecordError(err)
		return fmt.Errorf("failed to compress data: %w", err)
	}

	cmd := v.client.B().Set().Key(key).Value(string(compressedData))

	var cmdResult error
	if expiration > 0 {
		cmdResult = v.client.Do(ctx, cmd.Ex(expiration).Build()).Error()
	} else {
		cmdResult = v.client.Do(ctx, cmd.Build()).Error()
	}

	if cmdResult != nil {
		span.RecordError(cmdResult)
		return cmdResult
	}

	span.SetAttributes(attribute.String("valkey.result", "success"))

	return nil
}

// Get retrieves the value for a given key.
func (v *ValkeyStore) Get(ctx context.Context, key string) (interface{}, error) {
	ctx, span := v.tracer.Start(ctx, "valkey.get",
		trace.WithAttributes(
			attribute.String("valkey.key", key),
			attribute.String("valkey.operation", "get"),
		),
	)
	defer span.End()

	result := v.client.Do(ctx, v.client.B().Get().Key(key).Build())
	if result.Error() != nil {
		if handled, err := v.handleValkeyNilError(result.Error(), span, "key_not_found"); handled {
			return nil, err
		}
	}

	data, err := result.ToString()
	if err != nil {
		span.RecordError(err)
		return nil, fmt.Errorf("failed to convert result to string: %w", err)
	}

	span.SetAttributes(attribute.Int("data.raw.size.bytes", len(data)))

	// Decompress the data if compression is enabled
	decompressedData, err := v.decompress(ctx, []byte(data))
	if err != nil {
		span.RecordError(err)
		return nil, fmt.Errorf("failed to decompress data: %w", err)
	}

	var value interface{}
	if err := json.Unmarshal(decompressedData, &value); err != nil {
		span.RecordError(err)
		return nil, fmt.Errorf("failed to unmarshal value: %w", err)
	}

	span.SetAttributes(
		attribute.String("valkey.result", "success"),
		attribute.Int("data.unmarshaled.size.bytes", len(decompressedData)),
	)

	return value, nil
}

// Delete removes a key-value pair.
func (v *ValkeyStore) Delete(ctx context.Context, key string) error {
	ctx, span := v.tracer.Start(ctx, "valkey.delete",
		trace.WithAttributes(
			attribute.String("valkey.key", key),
			attribute.String("valkey.operation", "delete"),
		),
	)
	defer span.End()

	err := v.client.Do(ctx, v.client.B().Del().Key(key).Build()).Error()
	if err != nil {
		span.RecordError(err)
		return err
	}

	span.SetAttributes(attribute.String("valkey.result", "success"))

	return nil
}

// Exists checks if a key exists in the store.
func (v *ValkeyStore) Exists(ctx context.Context, key string) (bool, error) {
	ctx, span := v.tracer.Start(ctx, "valkey.exists",
		trace.WithAttributes(
			attribute.String("valkey.key", key),
			attribute.String("valkey.operation", "exists"),
		),
	)
	defer span.End()

	result := v.client.Do(ctx, v.client.B().Exists().Key(key).Build())
	if result.Error() != nil {
		if handled, err := v.handleValkeyNilError(result.Error(), span, "key_not_found"); handled {
			return false, err
		}

		return false, result.Error()
	}

	count, err := result.ToInt64()
	if err != nil {
		span.RecordError(err)
		return false, err
	}

	exists := count > 0
	span.SetAttributes(
		attribute.Bool("valkey.key.exists", exists),
		attribute.String("valkey.result", "success"),
	)

	return exists, nil
}

// Ping checks the connection to the Valkey server.
func (v *ValkeyStore) Ping(ctx context.Context) (string, error) {
	ctx, span := v.tracer.Start(ctx, "valkey.ping",
		trace.WithAttributes(
			attribute.String("valkey.operation", "ping"),
		),
	)
	defer span.End()

	result := v.client.Do(ctx, v.client.B().Ping().Build())
	if result.Error() != nil {
		span.RecordError(result.Error())
		return "", result.Error()
	}

	response, err := result.ToString()
	if err != nil {
		span.RecordError(err)
		return "", err
	}

	span.SetAttributes(
		attribute.String("valkey.ping.response", response),
		attribute.String("valkey.result", "success"),
	)

	return response, nil
}

// Close closes the Valkey client connection.
func (v *ValkeyStore) Close() error {
	_, span := v.tracer.Start(context.Background(), "valkey.close",
		trace.WithAttributes(
			attribute.String("valkey.operation", "close"),
		),
	)
	defer span.End()

	v.client.Close()
	span.SetAttributes(attribute.String("valkey.result", "success"))

	return nil
}

// StoreCachedPolicyResults caches policy evaluation results with size validation
func (v *ValkeyStore) StoreCachedPolicyResults(
	ctx context.Context,
	key string,
	result interface{},
	ttl time.Duration,
	maxSize int64,
) error {
	ctx, span := v.tracer.Start(ctx, "valkey.store_policy_cache",
		trace.WithAttributes(
			attribute.String("valkey.operation", "store_policy_cache"),
			attribute.String("cache.key", key),
			attribute.String("cache.ttl", ttl.String()),
			attribute.Int64("cache.max_size_bytes", maxSize),
		),
	)
	defer span.End()

	now := time.Now()
	entry := &PolicyCacheEntry{
		Result:    result,
		CachedAt:  now,
		ExpiresAt: now.Add(ttl),
		Size:      0, // Will be set after serialization
	}

	// Serialize the cache entry
	data, err := json.Marshal(entry)
	if err != nil {
		span.RecordError(err)
		return fmt.Errorf("failed to marshal cache entry: %w", err)
	}

	dataSize := int64(len(data))
	entry.Size = dataSize

	span.SetAttributes(
		attribute.Int64("cache.size_bytes", dataSize),
		attribute.Bool("valkey.compression_enabled", v.enableCompression),
	)

	// Check size limit before processing
	if maxSize > 0 && dataSize > maxSize {
		span.SetAttributes(attribute.Bool("cache.size_exceeded", true))
		return ErrEntrySizeExceeded
	}

	// Apply compression if enabled
	if v.enableCompression {
		compressedData, err := v.compress(ctx, data)
		if err != nil {
			span.RecordError(err)
			return fmt.Errorf("failed to compress cache entry: %w", err)
		}

		data = compressedData
		span.SetAttributes(
			attribute.Int64("valkey.compressed_size", int64(len(data))),
			attribute.Float64("valkey.compression_ratio", float64(len(data))/float64(dataSize)),
		)
	}

	// Store in Valkey with TTL
	setResult := v.client.Do(
		ctx,
		v.client.B().Set().Key(key).Value(valkey.BinaryString(data)).Ex(ttl).Build(),
	)
	if setResult.Error() != nil {
		span.RecordError(setResult.Error())
		return fmt.Errorf("failed to store cache entry: %w", setResult.Error())
	}

	span.SetAttributes(
		attribute.Bool("cache.stored", true),
		attribute.String("valkey.result", "success"),
	)

	return nil
}

// GetCachedPolicyResults retrieves cached policy evaluation results
func (v *ValkeyStore) GetCachedPolicyResults(
	ctx context.Context,
	key string,
) (*PolicyCacheEntry, error) {
	ctx, span := v.tracer.Start(ctx, "valkey.get_policy_cache",
		trace.WithAttributes(
			attribute.String("valkey.operation", "get_policy_cache"),
			attribute.String("cache.key", key),
		),
	)
	defer span.End()

	// Get from Valkey
	result := v.client.Do(ctx, v.client.B().Get().Key(key).Build())
	if result.Error() != nil {
		if valkey.IsValkeyNil(result.Error()) {
			span.SetAttributes(
				attribute.Bool("cache.hit", false),
				attribute.String("cache.miss_reason", "not_found"),
			)

			return nil, ErrKeyNotFound
		}

		span.RecordError(result.Error())

		return nil, fmt.Errorf("failed to get cache entry: %w", result.Error())
	}

	data, err := result.AsBytes()
	if err != nil {
		span.RecordError(err)
		return nil, fmt.Errorf("failed to read cache entry: %w", err)
	}

	originalSize := int64(len(data))
	span.SetAttributes(
		attribute.Int64("valkey.data_size", originalSize),
		attribute.Bool("valkey.compression_enabled", v.enableCompression),
	)

	// Decompress if compression is enabled
	if v.enableCompression {
		decompressedData, err := v.decompress(ctx, data)
		if err != nil {
			span.RecordError(err)
			return nil, fmt.Errorf("failed to decompress cache entry: %w", err)
		}

		data = decompressedData
		span.SetAttributes(
			attribute.Int64("valkey.decompressed_size", int64(len(data))),
			attribute.Float64("valkey.compression_ratio", float64(originalSize)/float64(len(data))),
		)
	}

	// Deserialize the cache entry
	var entry PolicyCacheEntry
	if err := json.Unmarshal(data, &entry); err != nil {
		span.RecordError(err)
		return nil, fmt.Errorf("failed to unmarshal cache entry: %w", err)
	}

	// Check if entry has expired (additional safety check)
	if time.Now().After(entry.ExpiresAt) {
		span.SetAttributes(
			attribute.Bool("cache.hit", false),
			attribute.String("cache.miss_reason", "expired"),
		)
		// Clean up expired entry
		go func() {
			deleteCtx := context.Background()
			v.client.Do(deleteCtx, v.client.B().Del().Key(key).Build())
		}()

		return nil, ErrKeyNotFound
	}

	span.SetAttributes(
		attribute.Bool("cache.hit", true),
		attribute.Int64("cache.size_bytes", entry.Size),
		attribute.String("cache.cached_at", entry.CachedAt.Format(time.RFC3339)),
		attribute.String("cache.expires_at", entry.ExpiresAt.Format(time.RFC3339)),
		attribute.String("valkey.result", "success"),
	)

	return &entry, nil
}
