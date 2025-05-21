package config

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/TFMV/blackice/pkg/controlplane/crypto"
)

// ControlPlaneConfig defines the configuration parameters for the Control Plane Service
type ControlPlaneConfig struct {
	// Server configuration
	Server ServerConfig `json:"server"`

	// Auth service configuration
	Auth AuthConfig `json:"auth"`

	// Audit configuration
	Audit AuditConfig `json:"audit"`

	// Gateway configuration
	Gateway GatewayConfig `json:"gateway"`

	// Integration with other BlackIce services
	ServiceIntegration ServiceIntegrationConfig `json:"service_integration"`
}

// ServerConfig contains parameters for the Control Plane server
type ServerConfig struct {
	// Host address to bind the server to
	Host string `json:"host"`

	// Port to listen on
	Port int `json:"port"`

	// TLS configuration for secure communication
	TLS TLSConfig `json:"tls"`

	// Timeout settings
	ReadTimeoutSeconds  int `json:"read_timeout_seconds"`
	WriteTimeoutSeconds int `json:"write_timeout_seconds"`
	IdleTimeoutSeconds  int `json:"idle_timeout_seconds"`

	// Maximum request size in bytes
	MaxRequestSizeBytes int64 `json:"max_request_size_bytes"`

	// Maximum concurrent requests
	MaxConcurrentRequests int `json:"max_concurrent_requests"`
}

// TLSConfig contains TLS settings
type TLSConfig struct {
	// Whether to enable TLS
	Enabled bool `json:"enabled"`

	// Path to certificate file
	CertFile string `json:"cert_file"`

	// Path to key file
	KeyFile string `json:"key_file"`

	// Path to CA certificate for client verification
	CAFile string `json:"ca_file"`

	// Whether to require client certificates
	RequireClientCert bool `json:"require_client_cert"`

	// Minimum TLS version (e.g., "1.2", "1.3")
	MinVersion string `json:"min_version"`

	// Use quantum-resistant algorithms if available
	UseQuantumResistantAlgorithms bool `json:"use_quantum_resistant_algorithms"`
}

// AuthConfig contains authentication and authorization settings
type AuthConfig struct {
	// Token settings
	TokenExpiryMinutes     int    `json:"token_expiry_minutes"`
	RefreshTokenExpiryDays int    `json:"refresh_token_expiry_days"`
	TokenSigningKey        string `json:"token_signing_key"`
	TokenIssuer            string `json:"token_issuer"`

	// Password policy
	PasswordPolicy PasswordPolicy `json:"password_policy"`

	// MFA settings
	RequireMFA                 bool     `json:"require_mfa"`
	AllowedMFAMethods          []string `json:"allowed_mfa_methods"`
	AttestationChallengeExpiry int      `json:"attestation_challenge_expiry_seconds"`

	// Session settings
	MaxConcurrentSessions int `json:"max_concurrent_sessions"`
	SessionIdleTimeout    int `json:"session_idle_timeout_minutes"`

	// Rate limiting
	FailedLoginLockoutThreshold int `json:"failed_login_lockout_threshold"`
	LockoutDurationMinutes      int `json:"lockout_duration_minutes"`
}

// PasswordPolicy defines password requirements
type PasswordPolicy struct {
	MinLength                int  `json:"min_length"`
	RequireUppercase         bool `json:"require_uppercase"`
	RequireLowercase         bool `json:"require_lowercase"`
	RequireNumbers           bool `json:"require_numbers"`
	RequireSpecialCharacters bool `json:"require_special_characters"`
	PreventPasswordReuse     int  `json:"prevent_password_reuse"`
	PasswordExpiryDays       int  `json:"password_expiry_days"`
}

// AuditConfig contains settings for audit logging
type AuditConfig struct {
	// Whether to enable detailed audit logging
	Enabled bool `json:"enabled"`

	// Log storage settings
	StoragePath       string `json:"storage_path"`
	RetentionDays     int    `json:"retention_days"`
	EncryptionEnabled bool   `json:"encryption_enabled"`

	// Which events to log
	LogAuthEvents   bool `json:"log_auth_events"`
	LogAdminEvents  bool `json:"log_admin_events"`
	LogSystemEvents bool `json:"log_system_events"`
	LogDataAccess   bool `json:"log_data_access"`

	// Whether to include payload data in logs
	IncludeRequestData  bool `json:"include_request_data"`
	IncludeResponseData bool `json:"include_response_data"`

	// Whether to verify attestations on logged events
	VerifyAttestations bool `json:"verify_attestations"`
}

// GatewayConfig contains API gateway settings
type GatewayConfig struct {
	// Host address to bind the gateway to
	Host string `json:"host"`

	// Port to listen on
	Port int `json:"port"`

	// Rate limiting
	EnableRateLimiting bool   `json:"enable_rate_limiting"`
	DefaultRateLimit   int    `json:"default_rate_limit"`
	RateLimitWindow    string `json:"rate_limit_window"`

	// CORS settings
	EnableCORS       bool     `json:"enable_cors"`
	AllowedOrigins   []string `json:"allowed_origins"`
	AllowedMethods   []string `json:"allowed_methods"`
	AllowedHeaders   []string `json:"allowed_headers"`
	AllowCredentials bool     `json:"allow_credentials"`

	// API versioning
	DefaultAPIVersion string   `json:"default_api_version"`
	SupportedVersions []string `json:"supported_versions"`
}

// ServiceIntegrationConfig contains settings for integration with other BlackIce services
type ServiceIntegrationConfig struct {
	// Storage service integration
	StorageService ServiceEndpoint `json:"storage_service"`

	// Panic service integration
	PanicService ServiceEndpoint `json:"panic_service"`

	// Attestation service integration
	AttestationService ServiceEndpoint `json:"attestation_service"`

	// Ledger service integration
	LedgerService ServiceEndpoint `json:"ledger_service"`
}

// ServiceEndpoint defines connection details for a service
type ServiceEndpoint struct {
	Host           string            `json:"host"`
	Port           int               `json:"port"`
	UseTLS         bool              `json:"use_tls"`
	TimeoutSeconds int               `json:"timeout_seconds"`
	Metadata       map[string]string `json:"metadata"`
}

// LoadConfig loads the configuration from a JSON file
func LoadConfig(path string) (*ControlPlaneConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("error reading config file: %w", err)
	}

	var config ControlPlaneConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("error parsing config file: %w", err)
	}

	if err := validateConfig(&config); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	return &config, nil
}

// validateConfig performs validation on the configuration
func validateConfig(config *ControlPlaneConfig) error {
	// Validate server config
	if config.Server.Port <= 0 || config.Server.Port > 65535 {
		return fmt.Errorf("invalid server port: %d", config.Server.Port)
	}

	// Validate TLS config when enabled
	if config.Server.TLS.Enabled {
		if config.Server.TLS.CertFile == "" || config.Server.TLS.KeyFile == "" {
			return fmt.Errorf("TLS enabled but certificate or key file not specified")
		}
	}

	// Validate auth config
	if config.Auth.TokenExpiryMinutes <= 0 {
		return fmt.Errorf("token expiry must be positive")
	}

	// Check if quantum resistant algorithms are requested but not available
	if config.Server.TLS.UseQuantumResistantAlgorithms {
		if !crypto.IsQuantumResistantAvailable() {
			return fmt.Errorf("quantum-resistant algorithms requested but not available")
		}
	}

	return nil
}

// DefaultConfig returns a default configuration
func DefaultConfig() *ControlPlaneConfig {
	return &ControlPlaneConfig{
		Server: ServerConfig{
			Host: "0.0.0.0",
			Port: 8443,
			TLS: TLSConfig{
				Enabled:                       true,
				RequireClientCert:             true,
				MinVersion:                    "1.3",
				UseQuantumResistantAlgorithms: false,
			},
			ReadTimeoutSeconds:    30,
			WriteTimeoutSeconds:   30,
			IdleTimeoutSeconds:    120,
			MaxRequestSizeBytes:   1048576, // 1MB
			MaxConcurrentRequests: 100,
		},
		Auth: AuthConfig{
			TokenExpiryMinutes:          60,
			RefreshTokenExpiryDays:      7,
			RequireMFA:                  true,
			AllowedMFAMethods:           []string{"totp", "hardware_key"},
			AttestationChallengeExpiry:  300, // 5 minutes
			MaxConcurrentSessions:       5,
			SessionIdleTimeout:          30, // 30 minutes
			FailedLoginLockoutThreshold: 5,
			LockoutDurationMinutes:      15,
			PasswordPolicy: PasswordPolicy{
				MinLength:                12,
				RequireUppercase:         true,
				RequireLowercase:         true,
				RequireNumbers:           true,
				RequireSpecialCharacters: true,
				PreventPasswordReuse:     10,
				PasswordExpiryDays:       90,
			},
		},
		Audit: AuditConfig{
			Enabled:            true,
			RetentionDays:      365,
			EncryptionEnabled:  true,
			LogAuthEvents:      true,
			LogAdminEvents:     true,
			LogSystemEvents:    true,
			LogDataAccess:      true,
			VerifyAttestations: true,
		},
		Gateway: GatewayConfig{
			Host:               "0.0.0.0",
			Port:               8080,
			EnableRateLimiting: true,
			DefaultRateLimit:   100,
			RateLimitWindow:    "1m",
			EnableCORS:         false,
			DefaultAPIVersion:  "v1",
			SupportedVersions:  []string{"v1"},
		},
		ServiceIntegration: ServiceIntegrationConfig{
			StorageService: ServiceEndpoint{
				UseTLS:         true,
				TimeoutSeconds: 30,
			},
			PanicService: ServiceEndpoint{
				UseTLS:         true,
				TimeoutSeconds: 10,
			},
			AttestationService: ServiceEndpoint{
				UseTLS:         true,
				TimeoutSeconds: 15,
			},
			LedgerService: ServiceEndpoint{
				UseTLS:         true,
				TimeoutSeconds: 20,
			},
		},
	}
}

// SaveConfigToFile saves the configuration to a JSON file
func SaveConfigToFile(config *ControlPlaneConfig, path string) error {
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return fmt.Errorf("error marshaling config to JSON: %w", err)
	}

	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("error writing config file: %w", err)
	}

	return nil
}
