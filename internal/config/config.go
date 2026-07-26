package config

import "fmt"

// Config is the versioned gateway configuration.
type Config struct {
	Version  int            `yaml:"version" json:"version"`
	Server   ServerConfig   `yaml:"server" json:"server"`
	Database DatabaseConfig `yaml:"database" json:"database"`
	Auth     AuthConfig     `yaml:"auth" json:"auth"`
	Keys     KeyConfig      `yaml:"keys" json:"keys"`
	Backend  BackendConfig  `yaml:"backend" json:"backend"`
	Models   []ModelConfig  `yaml:"models" json:"models"`
}

// ServerConfig controls the client-facing HTTP server.
type ServerConfig struct {
	ListenAddress    string    `yaml:"listen_address" json:"listen_address"`
	MaxRequestBytes  int64     `yaml:"max_request_bytes" json:"max_request_bytes"`
	MaxResponseBytes int64     `yaml:"max_response_bytes" json:"max_response_bytes"`
	TLS              TLSConfig `yaml:"tls" json:"tls"`
}

// TLSConfig references the server certificate and private key.
type TLSConfig struct {
	CertificateFile string    `yaml:"certificate_file" json:"certificate_file"`
	PrivateKey      SecretRef `yaml:"private_key" json:"private_key"`
}

// DatabaseConfig references the PostgreSQL connection string.
type DatabaseConfig struct {
	DSN SecretRef `yaml:"dsn" json:"dsn"`
}

// AuthConfig configures caller authentication.
type AuthConfig struct {
	OIDC OIDCConfig `yaml:"oidc" json:"oidc"`
}

// OIDCConfig identifies the customer identity provider and expected audience.
type OIDCConfig struct {
	Issuer              string `yaml:"issuer" json:"issuer"`
	Audience            string `yaml:"audience" json:"audience"`
	JWKSURL             string `yaml:"jwks_url" json:"jwks_url"`
	JWKSCacheTTLSeconds int    `yaml:"jwks_cache_ttl_seconds" json:"jwks_cache_ttl_seconds"`
	GroupClaim          string `yaml:"group_claim" json:"group_claim"`
}

// KeyConfig keeps content evidence and audit signing keys separate.
type KeyConfig struct {
	ContentHMAC       SecretRef `yaml:"content_hmac" json:"content_hmac"`
	CheckpointSigning SecretRef `yaml:"checkpoint_signing" json:"checkpoint_signing"`
}

// BackendConfig identifies the existing OpenAI-compatible inference server.
type BackendConfig struct {
	BaseURL       string     `yaml:"base_url" json:"base_url"`
	Credential    *SecretRef `yaml:"credential,omitempty" json:"credential,omitempty"`
	AllowInsecure bool       `yaml:"allow_insecure,omitempty" json:"allow_insecure,omitempty"`
}

// ModelConfig maps a public model name to the backend model and integer pricing.
type ModelConfig struct {
	Name                             string `yaml:"name" json:"name"`
	BackendModel                     string `yaml:"backend_model" json:"backend_model"`
	InputCostMicrosPerMillionTokens  int64  `yaml:"input_cost_micros_per_million_tokens" json:"input_cost_micros_per_million_tokens"`
	OutputCostMicrosPerMillionTokens int64  `yaml:"output_cost_micros_per_million_tokens" json:"output_cost_micros_per_million_tokens"`
	MaxOutputTokens                  int64  `yaml:"max_output_tokens" json:"max_output_tokens"`
}

// SecretRef allows secret material to be referenced by file path or environment variable.
type SecretRef struct {
	File string `yaml:"file,omitempty" json:"file,omitempty"`
	Env  string `yaml:"env,omitempty" json:"env,omitempty"`
}

// String deliberately omits the referenced file path or environment variable.
func (ref SecretRef) String() string {
	switch {
	case !blank(ref.File):
		return "<secret-ref:file>"
	case !blank(ref.Env):
		return "<secret-ref:env>"
	default:
		return "<secret-ref:unset>"
	}
}

// Format prevents verbose and Go-syntax formatting from bypassing redaction.
func (ref SecretRef) Format(state fmt.State, _ rune) {
	fmt.Fprint(state, ref.String())
}

// String returns a safe configuration summary without secret references.
func (cfg Config) String() string {
	return fmt.Sprintf("Config{version:%d models:%d}", cfg.Version, len(cfg.Models))
}

// Format prevents recursive struct formatting from exposing secret references.
func (cfg Config) Format(state fmt.State, _ rune) {
	fmt.Fprint(state, cfg.String())
}
