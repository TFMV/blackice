package config

import (
	"fmt"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/spf13/viper"
)

// Config represents the top-level configuration
type Config struct {
	Server   ServerConfig   `mapstructure:"server"`
	Client   ClientConfig   `mapstructure:"client"`
	Security SecurityConfig `mapstructure:"security"`
	Logging  LoggingConfig  `mapstructure:"logging"`
	Proxy    ProxyConfig    `mapstructure:"proxy"`
}

// ServerConfig holds server-specific configuration
type ServerConfig struct {
	Host          string `mapstructure:"host"`
	Port          int    `mapstructure:"port"`
	TLSCertPath   string `mapstructure:"tls_cert_path"`
	TLSKeyPath    string `mapstructure:"tls_key_path"`
	TLSCACertPath string `mapstructure:"tls_ca_cert_path"`
	EnableMTLS    bool   `mapstructure:"enable_mtls"`
}

// ClientConfig holds client-specific configuration
type ClientConfig struct {
	UpstreamHost     string        `mapstructure:"upstream_host"`
	UpstreamPort     int           `mapstructure:"upstream_port"`
	TLSCertPath      string        `mapstructure:"tls_cert_path"`
	TLSKeyPath       string        `mapstructure:"tls_key_path"`
	TLSCACertPath    string        `mapstructure:"tls_ca_cert_path"`
	DisableTLSVerify bool          `mapstructure:"disable_tls_verify"`
	ConnectTimeout   time.Duration `mapstructure:"connect_timeout"`
	RequestTimeout   time.Duration `mapstructure:"request_timeout"`
}

// SecurityConfig holds security-specific configuration
type SecurityConfig struct {
	EnableHMAC          bool   `mapstructure:"enable_hmac"`
	HMACAlgorithm       string `mapstructure:"hmac_algorithm"`
	HMACSecretPath      string `mapstructure:"hmac_secret_path"`
	EnableAttestations  bool   `mapstructure:"enable_attestations"`
	EnableMerkleVerify  bool   `mapstructure:"enable_merkle_verify"`
	MinTrustScore       int    `mapstructure:"min_trust_score"`
	TrustScoreThreshold int    `mapstructure:"trust_score_threshold"`

	// Post-quantum security options
	EnablePQTLS    bool   `mapstructure:"enable_pq_tls"`
	PQTLSAlgorithm string `mapstructure:"pq_tls_algorithm"`
	HybridMode     bool   `mapstructure:"hybrid_mode"`
}

// LoggingConfig holds logging-specific configuration
type LoggingConfig struct {
	Level           string   `mapstructure:"level"`
	Format          string   `mapstructure:"format"`
	TimestampFormat string   `mapstructure:"timestamp_format"`
	OutputPaths     []string `mapstructure:"output_paths"`
	File            string   `mapstructure:"file"`         // Path to log file
	EnableJSON      bool     `mapstructure:"enable_json"`  // Enable JSON logging
	EnableTrace     bool     `mapstructure:"enable_trace"` // Enable trace IDs in logs
}

// ProxyConfig holds proxy-specific configuration
type ProxyConfig struct {
	Mode            string `mapstructure:"mode"` // pass-through, trust-boundary, transform
	EnableMetrics   bool   `mapstructure:"enable_metrics"`
	MetricsAddr     string `mapstructure:"metrics_addr"`
	AdminAPIEnabled bool   `mapstructure:"admin_api_enabled"`
	AdminAPIAddr    string `mapstructure:"admin_api_addr"`
}

// LoadConfig loads the configuration from the specified file and environments
func LoadConfig(configPath string) (*Config, error) {
	v := viper.New()

	// Set default configuration values
	setDefaultConfig(v)

	// Set up environment variables
	v.SetEnvPrefix("BLACKICE")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()

	// Read configuration file if provided
	if configPath != "" {
		v.SetConfigFile(configPath)
		if err := v.ReadInConfig(); err != nil {
			return nil, fmt.Errorf("failed to read config file: %w", err)
		}
		log.Info().Str("config_file", configPath).Msg("Loaded configuration file")
	} else {
		log.Info().Msg("No configuration file provided, using environment variables and defaults")
	}

	// Parse configuration
	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	return &cfg, nil
}

// setDefaultConfig sets the default configuration values
func setDefaultConfig(v *viper.Viper) {
	// Server defaults
	v.SetDefault("server.host", "0.0.0.0")
	v.SetDefault("server.port", 8081)
	v.SetDefault("server.enable_mtls", false)

	// Client defaults
	v.SetDefault("client.upstream_host", "localhost")
	v.SetDefault("client.upstream_port", 8080)
	v.SetDefault("client.disable_tls_verify", false)
	v.SetDefault("client.connect_timeout", "10s")
	v.SetDefault("client.request_timeout", "30s")

	// Security defaults
	v.SetDefault("security.enable_hmac", false)
	v.SetDefault("security.hmac_algorithm", "SHA256")
	v.SetDefault("security.enable_attestations", false)
	v.SetDefault("security.enable_merkle_verify", false)
	v.SetDefault("security.min_trust_score", 0)
	v.SetDefault("security.trust_score_threshold", 50)
	v.SetDefault("security.enable_pq_tls", false)
	v.SetDefault("security.pq_tls_algorithm", "KYBER768")
	v.SetDefault("security.hybrid_mode", true)

	// Logging defaults
	v.SetDefault("logging.level", "info")
	v.SetDefault("logging.format", "json")
	v.SetDefault("logging.timestamp_format", time.RFC3339)
	v.SetDefault("logging.output_paths", []string{"stdout"})
	v.SetDefault("logging.file", "")
	v.SetDefault("logging.enable_json", true)
	v.SetDefault("logging.enable_trace", false)

	// Proxy defaults
	v.SetDefault("proxy.mode", "pass-through")
	v.SetDefault("proxy.enable_metrics", false)
	v.SetDefault("proxy.metrics_addr", ":9090")
	v.SetDefault("proxy.admin_api_enabled", false)
	v.SetDefault("proxy.admin_api_addr", ":9091")
}
