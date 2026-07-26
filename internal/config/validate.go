package config

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

const supportedVersion = 1

var oidcGroupClaimNamePattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_./-]{0,63}$`)

// FieldError reports a configuration problem without rendering its value.
type FieldError struct {
	Field   string
	Problem string
}

func (err *FieldError) Error() string {
	return fmt.Sprintf("configuration field %q %s", err.Field, err.Problem)
}

// Validate checks the required V1 configuration contract.
func Validate(cfg Config) error {
	if cfg.Version != supportedVersion {
		return invalid("version", "must equal 1")
	}
	if blank(cfg.Server.ListenAddress) {
		return required("server.listen_address")
	}
	if cfg.Server.MaxRequestBytes <= 0 {
		return required("server.max_request_bytes")
	}
	if cfg.Server.MaxResponseBytes <= 0 {
		return required("server.max_response_bytes")
	}
	if blank(cfg.Server.TLS.CertificateFile) {
		return required("server.tls.certificate_file")
	}
	if err := validateSecretRef("server.tls.private_key", cfg.Server.TLS.PrivateKey, true); err != nil {
		return err
	}
	if err := validateSecretRef("database.dsn", cfg.Database.DSN, true); err != nil {
		return err
	}
	if blank(cfg.Auth.OIDC.Issuer) {
		return required("auth.oidc.issuer")
	}
	if err := validateOIDCIssuer(cfg.Auth.OIDC.Issuer); err != nil {
		return err
	}
	if blank(cfg.Auth.OIDC.Audience) {
		return required("auth.oidc.audience")
	}
	if blank(cfg.Auth.OIDC.JWKSURL) {
		return required("auth.oidc.jwks_url")
	}
	if err := validateOIDCJWKSURL(cfg.Auth.OIDC.JWKSURL); err != nil {
		return err
	}
	if cfg.Auth.OIDC.JWKSCacheTTLSeconds <= 0 || cfg.Auth.OIDC.JWKSCacheTTLSeconds > 86400 {
		return invalid("auth.oidc.jwks_cache_ttl_seconds", "must be between 1 and 86400")
	}
	if blank(cfg.Auth.OIDC.GroupClaim) {
		return required("auth.oidc.group_claim")
	}
	if !oidcGroupClaimNamePattern.MatchString(cfg.Auth.OIDC.GroupClaim) {
		return invalid("auth.oidc.group_claim", "must be a bounded claim name")
	}
	if err := validateSecretRef("keys.content_hmac", cfg.Keys.ContentHMAC, true); err != nil {
		return err
	}
	if err := validateSecretRef("keys.checkpoint_signing", cfg.Keys.CheckpointSigning, true); err != nil {
		return err
	}
	if cfg.Backend.Credential != nil {
		if err := validateSecretRef("backend.credential", *cfg.Backend.Credential, true); err != nil {
			return err
		}
	}
	if blank(cfg.Backend.BaseURL) {
		return required("backend.base_url")
	}
	if err := validateBackendURL(cfg.Backend); err != nil {
		return err
	}
	if len(cfg.Models) == 0 {
		return required("models")
	}

	modelNames := make(map[string]struct{}, len(cfg.Models))
	for index, model := range cfg.Models {
		prefix := fmt.Sprintf("models[%d]", index)
		if blank(model.Name) {
			return required(prefix + ".name")
		}
		if _, exists := modelNames[model.Name]; exists {
			return invalid(prefix+".name", "must be unique")
		}
		modelNames[model.Name] = struct{}{}
		if blank(model.BackendModel) {
			return required(prefix + ".backend_model")
		}
		if model.InputCostMicrosPerMillionTokens <= 0 {
			return required(prefix + ".input_cost_micros_per_million_tokens")
		}
		if model.OutputCostMicrosPerMillionTokens <= 0 {
			return required(prefix + ".output_cost_micros_per_million_tokens")
		}
		if model.MaxOutputTokens <= 0 {
			return required(prefix + ".max_output_tokens")
		}
	}

	return nil
}

func validateOIDCIssuer(issuer string) error {
	parsed, err := url.Parse(issuer)
	if err != nil || parsed.Hostname() == "" || !strings.HasPrefix(issuer, "https://") {
		return invalid("auth.oidc.issuer", "must be an absolute HTTPS URL")
	}
	if parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return invalid("auth.oidc.issuer", "must not contain credentials, a query, or a fragment")
	}
	return nil
}

func validateOIDCJWKSURL(raw string) error {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Hostname() == "" || !strings.HasPrefix(raw, "https://") {
		return invalid("auth.oidc.jwks_url", "must be an absolute HTTPS URL")
	}
	if parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return invalid("auth.oidc.jwks_url", "must not contain credentials, a query, or a fragment")
	}
	return nil
}

func validateBackendURL(backend BackendConfig) error {
	parsed, err := url.Parse(backend.BaseURL)
	if err != nil || parsed.Hostname() == "" {
		return invalid("backend.base_url", "must be an absolute HTTP or HTTPS URL")
	}
	if parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return invalid("backend.base_url", "must not contain credentials, a query, or a fragment")
	}

	switch {
	case strings.HasPrefix(backend.BaseURL, "https://"):
		return nil
	case strings.HasPrefix(backend.BaseURL, "http://"):
		if backend.AllowInsecure || isLoopbackHost(parsed.Hostname()) {
			return nil
		}
		return invalid("backend.base_url", "requires HTTPS unless loopback or allow_insecure is true")
	default:
		return invalid("backend.base_url", "must use lowercase HTTP or HTTPS")
	}
}

func isLoopbackHost(host string) bool {
	return host == "localhost" || host == "127.0.0.1" || host == "::1"
}

func validateSecretRef(field string, ref SecretRef, requiredRef bool) error {
	hasFile := !blank(ref.File)
	hasEnv := !blank(ref.Env)

	if hasFile && hasEnv {
		return invalid(field, "must reference exactly one of file or env")
	}
	if requiredRef && !hasFile && !hasEnv {
		return required(field)
	}
	return nil
}

func blank(value string) bool {
	return strings.TrimSpace(value) == ""
}

func required(field string) error {
	return &FieldError{Field: field, Problem: "is required"}
}

func invalid(field, problem string) error {
	return &FieldError{Field: field, Problem: problem}
}
