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

	"github.com/terrpan/polly/internal/config"
	"github.com/valkey-io/valkey-go"
	"github.com/valkey-io/valkey-go/valkeyotel"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

// ValkeyStore implements Store interface using Valkey storage.
type ValkeyStore struct {
	client            valkey.Client
	enableCompression bool
	logger            *slog.Logger
	tracer            trace.Tracer
}

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
			Username: cfg.Username,
			Password: cfg.Password,
			SelectDB: cfg.DB,
		}
		logger.Info("Configuring Valkey with Sentinel",
			"master", cfg.SentinelMaster,
			"sentinels", len(cfg.SentinelAddrs))
	} else {
		// Standard configuration
		clientOpts = valkey.ClientOption{
			InitAddress: []string{cfg.Address},
			Username:    cfg.Username,
			Password:    cfg.Password,
			SelectDB:    cfg.DB,
		}
		logger.Info("Configuring Valkey with direct connection", "address", cfg.Address)
	}

	var client valkey.Client
	var err error

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
		store.Close() // Clean up the client
		return nil, fmt.Errorf("failed to connect to Valkey server: %w", err)
	}

	if cfg.EnableCompression {
		logger.Info("Valkey compression enabled")
	}

	return store, nil
}

// compress compresses data using zlib if compression is enabled
func (v *ValkeyStore) compress(ctx context.Context, data []byte) ([]byte, error) {
	ctx, span := v.tracer.Start(ctx, "valkey.compress",
		trace.WithAttributes(
			attribute.Int("data.size.bytes", len(data)),
			attribute.Bool("compression.enabled", v.enableCompression),
		),
	)
	defer span.End()

	if !v.enableCompression {
		span.SetAttributes(attribute.String("compression.status", "disabled"))
		return data, nil
	}

	var buf bytes.Buffer
	writer := zlib.NewWriter(&buf)

	if _, err := writer.Write(data); err != nil {
		writer.Close()
		span.RecordError(err)
		return nil, fmt.Errorf("failed to compress data: %w", err)
	}

	if err := writer.Close(); err != nil {
		span.RecordError(err)
		return nil, fmt.Errorf("failed to close compressor: %w", err)
	}

	compressed := buf.Bytes()
	span.SetAttributes(
		attribute.Int("data.compressed.size.bytes", len(compressed)),
		attribute.Float64("compression.ratio", float64(len(data))/float64(len(compressed))),
		attribute.String("compression.status", "completed"),
	)

	return compressed, nil
}

// decompress decompresses data using zlib if compression is enabled
func (v *ValkeyStore) decompress(ctx context.Context, data []byte) ([]byte, error) {
	ctx, span := v.tracer.Start(ctx, "valkey.decompress",
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

	reader, err := zlib.NewReader(bytes.NewReader(data))
	if err != nil {
		span.RecordError(err)
		return nil, fmt.Errorf("failed to create decompressor: %w", err)
	}
	defer reader.Close()

	decompressed, err := io.ReadAll(reader)
	if err != nil {
		span.RecordError(err)
		return nil, fmt.Errorf("failed to decompress data: %w", err)
	}

	span.SetAttributes(
		attribute.Int("data.decompressed.size.bytes", len(decompressed)),
		attribute.Float64("compression.ratio", float64(len(decompressed))/float64(len(data))),
		attribute.String("compression.status", "completed"),
	)

	return decompressed, nil
}

// Set stores a value with the given key and expiration.
func (v *ValkeyStore) Set(ctx context.Context, key string, value interface{}, expiration time.Duration) error {
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
		if valkey.IsValkeyNil(result.Error()) {
			span.SetAttributes(attribute.String("valkey.result", "key_not_found"))
			return nil, ErrKeyNotFound
		}
		span.RecordError(result.Error())
		return nil, result.Error()
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
		if valkey.IsValkeyNil(result.Error()) {
			span.SetAttributes(
				attribute.Bool("valkey.key.exists", false),
				attribute.String("valkey.result", "key_not_found"),
			)
			return false, ErrKeyNotFound
		}
		span.RecordError(result.Error())
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
