package config

import (
	"fmt"
	"net/url"
	"os"
	"reflect"
	"strings"
	"time"

	"github.com/spf13/viper"

	"github.com/terrpan/polly/internal/clients"
)

const (
	envPrefix = "polly" // Prefix for application name used for environment variables
)

// Config represents the configuration of the application. Each field corresponds to a configuration option
type Config struct {
	Opa         OpaConfig `mapstructure:"opa"`
	GitHubToken string    `mapstructure:"github_token"`
	Version     string
	Commit      string
	BuildTime   string
	Logger      LoggerConfig    `mapstructure:"logger"`
	GitHubApp   GitHubAppConfig `mapstructure:"github"`
	Storage     StorageConfig   `mapstructure:"storage"`
	Port        int             `mapstructure:"port"`
	OTLP        OTLPConfig      `mapstructure:"otlp"`
}

// GitHubAppConfig represents the configuration for a GitHub App
type GitHubAppConfig struct {
	PrivateKeyPath string `mapstructure:"private_key_path"`
	PrivateKey     string `mapstructure:"private_key"`
	BaseURL        string `mapstructure:"base_url"`
	UploadURL      string `mapstructure:"upload_url"`
	AppID          int64  `mapstructure:"app_id"`
	InstallationID int64  `mapstructure:"installation_id"`
}

// LoggerConfig represents the configuration for the logger
type LoggerConfig struct {
	Level      string `mapstructure:"level"`
	JSONOutput bool   `mapstructure:"json_output"`
	AddSource  bool   `mapstructure:"add_source"`
}

// OpaConfig represents the configuration for OPA (Open Policy Agent)
type OpaConfig struct {
	// OPA server URL
	ServerURL string `mapstructure:"server_url"`
	// OPA policy path
	PolicyPath string `mapstructure:"policy_path"`
	// OPA bundle path
	BundlePath string `mapstructure:"bundle_path"`
	// OPA bundle refresh interval
	BundleRefreshInterval string `mapstructure:"bundle_refresh_interval"`
}

// OTLPConfig represents the configuration for OpenTelemetry
type OTLPConfig struct {
	EnableOTLP         bool `mapstructure:"enable_otlp"`
	EnableOTLPExporter bool `mapstructure:"enable_otlp_exporter"` // TODO: Implement this
	OTLPStdOut         bool `mapstructure:"otlp_stdout"`
}

// StorageConfig represents the configuration for storage
type StorageConfig struct {
	Type                 string            `mapstructure:"type"`
	DefaultKeyExpiration string            `mapstructure:"default_key_expiration"`
	PolicyCache          PolicyCacheConfig `mapstructure:"policy_cache"`
	Valkey               ValkeyConfig      `mapstructure:"valkey"`
}

// PolicyCacheConfig holds configuration for caching policy evaluation results
type PolicyCacheConfig struct {
	TTL     string `mapstructure:"ttl"`
	MaxSize int64  `mapstructure:"max_size"`
	Enabled bool   `mapstructure:"enabled"`
}

// ValkeyConfig holds the configuration for connecting to Valkey
type ValkeyConfig struct {
	Address           string   `mapstructure:"address"`
	Username          string   `mapstructure:"username"`
	Password          string   `mapstructure:"password"`
	SentinelMaster    string   `mapstructure:"sentinel_master"`
	SentinelUsername  string   `mapstructure:"sentinel_username"`
	SentinelPassword  string   `mapstructure:"sentinel_password"`
	SentinelAddrs     []string `mapstructure:"sentinel_addrs"`
	DB                int      `mapstructure:"db"`
	EnableSentinel    bool     `mapstructure:"enable_sentinel"`
	EnableCompression bool     `mapstructure:"enable_compression"`
	EnableOTel        bool     `mapstructure:"enable_otel"`
}

var (
	// Version is the application version, can be overridden by build flags
	Version = "v0.0.1"
	// Commit is the git commit hash, can be overridden by build flags
	Commit = "unknown"
	// BuildTime is the build time, can be overridden by build flags
	BuildTime = "unknown"
)

var (
	// AppConfig is the globally accessible config
	AppConfig *Config
	// defaultConfig holds the built-in defaults
	defaultConfig = Config{
		Version: "v0.0.1",
		Port:    8080,
		Logger: LoggerConfig{
			Level:      "debug",
			JSONOutput: true,
			AddSource:  false,
		},
		GitHubApp: GitHubAppConfig{
			BaseURL:   "https://api.github.com",     // Default to GitHub.com API
			UploadURL: "https://uploads.github.com", // Default to GitHub.com uploads
		},
		Opa: OpaConfig{
			ServerURL:             "http://localhost:8181",
			PolicyPath:            "/v1/policies",
			BundlePath:            "/v1/bundles",
			BundleRefreshInterval: "5m",
		},
		OTLP: OTLPConfig{
			EnableOTLP: true,
			OTLPStdOut: false,
		},
		Storage: StorageConfig{
			Type:                 "memory", // Default to in-memory storage
			DefaultKeyExpiration: "24h",    // Expiration for keys
			Valkey: ValkeyConfig{
				Address:           "localhost:6379",
				Username:          "",
				Password:          "",
				DB:                0,
				EnableSentinel:    false,
				SentinelAddrs:     []string{},
				SentinelMaster:    "",
				SentinelUsername:  "",
				SentinelPassword:  "",
				EnableCompression: true,
				EnableOTel:        true,
			},
			PolicyCache: PolicyCacheConfig{
				Enabled: true,
				TTL:     "30m",
				MaxSize: 10 * 1024 * 1024, // 10MB default max size for cache entries
			},
		},
	}
)

// InitConfig initializes the configuration
func InitConfig() error {
	viper.SetEnvPrefix(envPrefix)
	viper.AutomaticEnv()

	// Configure Viper to handle nested structs
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))

	// Dynamically bind nested environment variables
	bindNestedEnvVars()

	// Dynamically set defaults from defaultConfig
	tmp := defaultConfig
	setDefaultsViaReflection(&tmp)

	AppConfig = &Config{}
	if err := viper.Unmarshal(AppConfig); err != nil {
		return fmt.Errorf("failed to unmarshal config: %w", err)
	}

	// Set build info from ldflags variables
	AppConfig.Version = Version
	AppConfig.Commit = Commit
	AppConfig.BuildTime = BuildTime

	return nil
}

// setDefaultsViaReflection reads each struct field's mapstructure tag
// and calls viper.SetDefault(tag, value) for that field.
func setDefaultsViaReflection(cfg interface{}) {
	setDefaultsRecursive(reflect.ValueOf(cfg).Elem(), reflect.TypeOf(cfg).Elem(), "")
}

// setDefaultsRecursive recursively sets defaults for nested structs
func setDefaultsRecursive(val reflect.Value, typ reflect.Type, keyPrefix string) {
	for i := 0; i < val.NumField(); i++ {
		fieldVal := val.Field(i)
		fieldType := typ.Field(i)

		// Skip unexported fields
		if !fieldType.IsExported() {
			continue
		}

		tag := fieldType.Tag.Get("mapstructure")
		if tag == "" || tag == "-" {
			continue
		}

		// Build the viper key
		var viperKey string
		if keyPrefix == "" {
			viperKey = tag
		} else {
			viperKey = keyPrefix + "." + tag
		}

		// Handle nested structs
		if fieldVal.Kind() == reflect.Struct {
			setDefaultsRecursive(fieldVal, fieldVal.Type(), viperKey)
		} else {
			// Set the default value
			viper.SetDefault(viperKey, fieldVal.Interface())
		}
	}
}

// GetDefaultConfig returns the default configuration. This is useful for testing or debugging.
func GetDefaultConfig() *Config {
	return &defaultConfig
}

// GetBuildInfo returns build information
func GetBuildInfo() (version, commit, buildTime string) {
	return Version, Commit, BuildTime
}

// LoadGitHubAppConfig loads GitHub App configuration and returns a client config
func LoadGitHubAppConfig() (*clients.GitHubAppConfig, error) {
	appConfig := AppConfig.GitHubApp

	if appConfig.AppID == 0 {
		return nil, fmt.Errorf("GITHUB_APP_ID is required")
	}

	if appConfig.InstallationID == 0 {
		return nil, fmt.Errorf("GITHUB_INSTALLATION_ID is required")
	}

	// Validate BaseURL if provided
	if appConfig.BaseURL != "" {
		if _, err := url.Parse(appConfig.BaseURL); err != nil {
			return nil, fmt.Errorf("invalid GITHUB_BASE_URL: %w", err)
		}
	}

	// Validate UploadURL if provided
	if appConfig.UploadURL != "" {
		if _, err := url.Parse(appConfig.UploadURL); err != nil {
			return nil, fmt.Errorf("invalid GITHUB_UPLOAD_URL: %w", err)
		}
	}

	var (
		privateKey []byte
		err        error
	)

	// Try to load private key from direct content first
	switch {
	case appConfig.PrivateKey != "":
		privateKey = []byte(appConfig.PrivateKey)
	case appConfig.PrivateKeyPath != "":
		// Load from file path
		privateKey, err = os.ReadFile(appConfig.PrivateKeyPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read private key file: %w", err)
		}
	default:
		return nil, fmt.Errorf("either GITHUB_PRIVATE_KEY or GITHUB_PRIVATE_KEY_PATH is required")
	}

	return &clients.GitHubAppConfig{
		AppID:          appConfig.AppID,
		InstallationID: appConfig.InstallationID,
		PrivateKey:     privateKey,
		BaseURL:        appConfig.BaseURL,
		UploadURL:      appConfig.UploadURL,
	}, nil
}

// IsGitHubAppConfigured checks if GitHub App configuration is available
func IsGitHubAppConfigured() bool {
	return AppConfig.GitHubApp.AppID != 0 &&
		AppConfig.GitHubApp.InstallationID != 0 &&
		(AppConfig.GitHubApp.PrivateKey != "" || AppConfig.GitHubApp.PrivateKeyPath != "")
}

// bindNestedEnvVars dynamically binds nested environment variables to Viper keys using reflection
func bindNestedEnvVars() {
	bindStructEnvVars(reflect.TypeOf(Config{}), "", envPrefix)
}

// bindStructEnvVars recursively binds struct fields to environment variables
func bindStructEnvVars(structType reflect.Type, keyPrefix, envPrefix string) {
	for i := 0; i < structType.NumField(); i++ {
		field := structType.Field(i)

		// Skip unexported fields
		if !field.IsExported() {
			continue
		}

		// Get the mapstructure tag
		tag := field.Tag.Get("mapstructure")
		if tag == "" || tag == "-" {
			continue
		}

		// Build the viper key (dot-separated)
		var viperKey string
		if keyPrefix == "" {
			viperKey = tag
		} else {
			viperKey = keyPrefix + "." + tag
		}

		// Build the environment variable name (underscore-separated, uppercase)
		envKey := envPrefix + "_" + strings.ToUpper(strings.ReplaceAll(viperKey, ".", "_"))

		// Check if this field is a struct (nested configuration)
		fieldType := field.Type
		if fieldType.Kind() == reflect.Struct {
			// Recursively handle nested structs
			bindStructEnvVars(fieldType, viperKey, envPrefix)
		} else {
			// Bind the environment variable to the viper key
			err := viper.BindEnv(viperKey, envKey)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error binding environment variable %s: %v\n", envKey, err)
			}
		}
	}
}

// GetDefaultExpiration returns the default expiration duration for keys
func GetDefaultExpiration() time.Duration {
	if AppConfig == nil || AppConfig.Storage.DefaultKeyExpiration == "" {
		return 24 * time.Hour // Default to 24 hours if not set
	}

	duration, err := time.ParseDuration(AppConfig.Storage.DefaultKeyExpiration)
	if err != nil {
		return 24 * time.Hour // Fallback to 24 hours on error
	}

	return duration
}

// GetPolicyCacheConfig returns the policy cache configuration with sensible defaults
func GetPolicyCacheConfig() PolicyCacheConfig {
	if AppConfig == nil {
		// Return default configuration when AppConfig is not initialized (e.g., in tests)
		return defaultConfig.Storage.PolicyCache
	}

	return AppConfig.Storage.PolicyCache
}
