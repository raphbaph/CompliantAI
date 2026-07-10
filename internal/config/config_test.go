package config

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"

	jsonschema "github.com/santhosh-tekuri/jsonschema/v6"
	"gopkg.in/yaml.v3"
)

const validMinimalYAML = `version: 1
server:
  listen_address: "127.0.0.1:8443"
  max_request_bytes: 1048576
  max_response_bytes: 4194304
  tls:
    certificate_file: "/etc/compliantai/tls/server.crt"
    private_key:
      file: "/run/secrets/tls-private-key"
database:
  dsn:
    env: "COMPLIANTAI_DATABASE_DSN"
auth:
  oidc:
    issuer: "https://idp.example.com"
    audience: "compliant-ai"
keys:
  content_hmac:
    file: "/run/secrets/content-hmac-key"
  checkpoint_signing:
    file: "/run/secrets/checkpoint-signing-key"
backend:
  base_url: "http://127.0.0.1:8000"
models:
  - name: "local-legal"
    backend_model: "qwen-local"
    input_cost_micros_per_million_tokens: 1000
    output_cost_micros_per_million_tokens: 2000
    max_output_tokens: 2048
`

func TestLoadValidMinimalConfig(t *testing.T) {
	cfg, err := Load(strings.NewReader(validMinimalYAML))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if cfg.Version != 1 {
		t.Fatalf("Version = %d, want 1", cfg.Version)
	}
	if cfg.Auth.OIDC.Issuer != "https://idp.example.com" {
		t.Fatalf("OIDC issuer = %q", cfg.Auth.OIDC.Issuer)
	}
	if cfg.Backend.BaseURL != "http://127.0.0.1:8000" {
		t.Fatalf("backend URL = %q", cfg.Backend.BaseURL)
	}
	if len(cfg.Models) != 1 || cfg.Models[0].Name != "local-legal" {
		t.Fatalf("models = %#v", cfg.Models)
	}
}

func TestLoadRejectsUnknownFields(t *testing.T) {
	_, err := Load(strings.NewReader(validMinimalYAML + "unknown_field: true\n"))
	if err == nil {
		t.Fatal("Load() error = nil, want unknown-field error")
	}
}

func TestLoadRejectsMultipleYAMLDocuments(t *testing.T) {
	_, err := Load(strings.NewReader(validMinimalYAML + "---\nversion: 1\n"))
	if err == nil {
		t.Fatal("Load() error = nil, want multiple-document error")
	}
}

func TestLoadRejectsMissingRequiredFields(t *testing.T) {
	tests := []struct {
		name        string
		old         string
		replacement string
		wantField   string
	}{
		{name: "version", old: "version: 1", replacement: "version: 0", wantField: "version"},
		{name: "listen address", old: `listen_address: "127.0.0.1:8443"`, replacement: `listen_address: ""`, wantField: "server.listen_address"},
		{name: "request limit", old: "max_request_bytes: 1048576", replacement: "max_request_bytes: 0", wantField: "server.max_request_bytes"},
		{name: "response limit", old: "max_response_bytes: 4194304", replacement: "max_response_bytes: 0", wantField: "server.max_response_bytes"},
		{name: "TLS certificate", old: `certificate_file: "/etc/compliantai/tls/server.crt"`, replacement: `certificate_file: ""`, wantField: "server.tls.certificate_file"},
		{name: "TLS private key", old: `file: "/run/secrets/tls-private-key"`, replacement: `file: ""`, wantField: "server.tls.private_key"},
		{name: "database DSN", old: `env: "COMPLIANTAI_DATABASE_DSN"`, replacement: `env: ""`, wantField: "database.dsn"},
		{name: "OIDC issuer", old: `issuer: "https://idp.example.com"`, replacement: `issuer: ""`, wantField: "auth.oidc.issuer"},
		{name: "OIDC audience", old: `audience: "compliant-ai"`, replacement: `audience: ""`, wantField: "auth.oidc.audience"},
		{name: "content HMAC key", old: `file: "/run/secrets/content-hmac-key"`, replacement: `file: ""`, wantField: "keys.content_hmac"},
		{name: "checkpoint signing key", old: `file: "/run/secrets/checkpoint-signing-key"`, replacement: `file: ""`, wantField: "keys.checkpoint_signing"},
		{name: "backend", old: `base_url: "http://127.0.0.1:8000"`, replacement: `base_url: ""`, wantField: "backend.base_url"},
		{name: "model name", old: `name: "local-legal"`, replacement: `name: ""`, wantField: "models[0].name"},
		{name: "backend model", old: `backend_model: "qwen-local"`, replacement: `backend_model: ""`, wantField: "models[0].backend_model"},
		{name: "input price", old: "input_cost_micros_per_million_tokens: 1000", replacement: "input_cost_micros_per_million_tokens: 0", wantField: "models[0].input_cost_micros_per_million_tokens"},
		{name: "output price", old: "output_cost_micros_per_million_tokens: 2000", replacement: "output_cost_micros_per_million_tokens: 0", wantField: "models[0].output_cost_micros_per_million_tokens"},
		{name: "output limit", old: "max_output_tokens: 2048", replacement: "max_output_tokens: 0", wantField: "models[0].max_output_tokens"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := strings.Replace(validMinimalYAML, tt.old, tt.replacement, 1)
			if input == validMinimalYAML {
				t.Fatalf("fixture does not contain %q", tt.old)
			}

			_, err := Load(strings.NewReader(input))
			if err == nil {
				t.Fatalf("Load() error = nil, want error for %s", tt.wantField)
			}
			if !strings.Contains(err.Error(), tt.wantField) {
				t.Fatalf("Load() error = %q, want field %q", err, tt.wantField)
			}
		})
	}
}

func TestLoadRejectsAmbiguousSecretReferenceWithoutLeaking(t *testing.T) {
	const fileCanary = "/run/secrets/DO-NOT-LEAK-FILE"
	const envCanary = "DO_NOT_LEAK_ENV"
	input := strings.Replace(
		validMinimalYAML,
		`content_hmac:
    file: "/run/secrets/content-hmac-key"`,
		`content_hmac:
    file: "`+fileCanary+`"
    env: "`+envCanary+`"`,
		1,
	)

	_, err := Load(strings.NewReader(input))
	if err == nil {
		t.Fatal("Load() error = nil, want ambiguous secret-reference error")
	}
	for _, canary := range []string{fileCanary, envCanary} {
		if strings.Contains(err.Error(), canary) {
			t.Fatalf("Load() error leaked secret reference %q: %v", canary, err)
		}
	}
}

func TestLoadRejectsScalarSecretReferenceWithoutLeaking(t *testing.T) {
	const canary = "DO-NOT-LEAK-SCALAR-SECRET"
	input := strings.Replace(
		validMinimalYAML,
		`content_hmac:
    file: "/run/secrets/content-hmac-key"`,
		`content_hmac: "`+canary+`"`,
		1,
	)

	_, err := Load(strings.NewReader(input))
	if err == nil {
		t.Fatal("Load() error = nil, want invalid secret-reference error")
	}
	if strings.Contains(err.Error(), canary) {
		t.Fatalf("Load() error leaked secret value %q: %v", canary, err)
	}
}

func TestConfigFormattingRedactsSecretReferences(t *testing.T) {
	cfg, err := Load(strings.NewReader(validMinimalYAML))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	rendered := fmt.Sprintf("%v | %+v | %#v", cfg, cfg, cfg)
	for _, secretReference := range []string{
		"/run/secrets/tls-private-key",
		"COMPLIANTAI_DATABASE_DSN",
		"/run/secrets/content-hmac-key",
		"/run/secrets/checkpoint-signing-key",
	} {
		if strings.Contains(rendered, secretReference) {
			t.Fatalf("formatted config leaked secret reference %q: %s", secretReference, rendered)
		}
	}
}

func TestLoadRejectsInsecureNonLoopbackBackend(t *testing.T) {
	input := strings.Replace(
		validMinimalYAML,
		`base_url: "http://127.0.0.1:8000"`,
		`base_url: "http://inference.internal:8000"`,
		1,
	)

	_, err := Load(strings.NewReader(input))
	if err == nil {
		t.Fatal("Load() error = nil, want insecure-backend error")
	}
	if !strings.Contains(err.Error(), "backend.base_url") {
		t.Fatalf("Load() error = %q, want backend.base_url", err)
	}
}

func TestLoadAllowsExplicitInsecureBackend(t *testing.T) {
	input := strings.Replace(
		validMinimalYAML,
		`base_url: "http://127.0.0.1:8000"`,
		"base_url: \"http://inference.internal:8000\"\n  allow_insecure: true",
		1,
	)

	if _, err := Load(strings.NewReader(input)); err != nil {
		t.Fatalf("Load() error = %v", err)
	}
}

func TestLoadRejectsDuplicateModelNames(t *testing.T) {
	const duplicateModel = `  - name: "local-legal"
    backend_model: "second-backend-model"
    input_cost_micros_per_million_tokens: 1000
    output_cost_micros_per_million_tokens: 2000
    max_output_tokens: 2048
`

	_, err := Load(strings.NewReader(validMinimalYAML + duplicateModel))
	if err == nil {
		t.Fatal("Load() error = nil, want duplicate-model error")
	}
	if !strings.Contains(err.Error(), "models[1].name") {
		t.Fatalf("Load() error = %q, want models[1].name", err)
	}
}

func TestLoadRejectsNegativeModelPrices(t *testing.T) {
	input := strings.Replace(
		validMinimalYAML,
		"input_cost_micros_per_million_tokens: 1000",
		"input_cost_micros_per_million_tokens: -1",
		1,
	)

	_, err := Load(strings.NewReader(input))
	if err == nil {
		t.Fatal("Load() error = nil, want negative-price error")
	}
	if !strings.Contains(err.Error(), "models[0].input_cost_micros_per_million_tokens") {
		t.Fatalf("Load() error = %q, want input price field", err)
	}
}

func TestExampleConfigLoads(t *testing.T) {
	file, err := os.Open("../../configs/example.yaml")
	if err != nil {
		t.Fatalf("open example config: %v", err)
	}
	defer file.Close()

	if _, err := Load(file); err != nil {
		t.Fatalf("Load(example.yaml) error = %v", err)
	}
}

func TestConfigSchemaIsStrictJSON(t *testing.T) {
	encoded, err := os.ReadFile("../../schemas/config-v1.schema.json")
	if err != nil {
		t.Fatalf("read config schema: %v", err)
	}

	var schema map[string]any
	if err := json.Unmarshal(encoded, &schema); err != nil {
		t.Fatalf("parse config schema: %v", err)
	}
	if additional, exists := schema["additionalProperties"]; !exists || additional != false {
		t.Fatalf("top-level additionalProperties = %#v, want false", additional)
	}
}

func TestSchemaAndLoaderValidationParity(t *testing.T) {
	tests := []struct {
		name       string
		configYAML string
		wantValid  bool
	}{
		{name: "valid loopback backend", configYAML: validMinimalYAML, wantValid: true},
		{
			name:       "loopback HTTP with redundant opt-in",
			configYAML: strings.Replace(validMinimalYAML, `base_url: "http://127.0.0.1:8000"`, "base_url: \"http://127.0.0.1:8000\"\n  allow_insecure: true", 1),
			wantValid:  true,
		},
		{
			name:       "loopback HTTP with null opt-in treated as absent",
			configYAML: strings.Replace(validMinimalYAML, `base_url: "http://127.0.0.1:8000"`, "base_url: \"http://127.0.0.1:8000\"\n  allow_insecure: null", 1),
			wantValid:  true,
		},
		{
			name:       "uppercase localhost is not canonical loopback",
			configYAML: strings.Replace(validMinimalYAML, "http://127.0.0.1:8000", "http://LOCALHOST:8000", 1),
			wantValid:  false,
		},
		{
			name:       "trailing-dot loopback is not canonical",
			configYAML: strings.Replace(validMinimalYAML, "http://127.0.0.1:8000", "http://127.0.0.1.:8000", 1),
			wantValid:  false,
		},
		{
			name:       "non-loopback HTTP without opt-in",
			configYAML: strings.Replace(validMinimalYAML, "http://127.0.0.1:8000", "http://inference.internal:8000", 1),
			wantValid:  false,
		},
		{
			name:       "non-loopback HTTP with opt-in",
			configYAML: strings.Replace(validMinimalYAML, `base_url: "http://127.0.0.1:8000"`, "base_url: \"http://inference.internal:8000\"\n  allow_insecure: true", 1),
			wantValid:  true,
		},
		{
			name:       "uppercase backend scheme",
			configYAML: strings.Replace(validMinimalYAML, "http://127.0.0.1:8000", "HTTP://127.0.0.1:8000", 1),
			wantValid:  false,
		},
		{
			name:       "unsupported backend scheme",
			configYAML: strings.Replace(validMinimalYAML, "http://127.0.0.1:8000", "ftp://127.0.0.1:8000", 1),
			wantValid:  false,
		},
		{
			name:       "backend URL credentials",
			configYAML: strings.Replace(validMinimalYAML, "http://127.0.0.1:8000", "https://user:password@inference.internal", 1),
			wantValid:  false,
		},
		{
			name:       "backend URL query",
			configYAML: strings.Replace(validMinimalYAML, "http://127.0.0.1:8000", "https://inference.internal?debug=true", 1),
			wantValid:  false,
		},
		{
			name:       "backend URL fragment",
			configYAML: strings.Replace(validMinimalYAML, "http://127.0.0.1:8000", "https://inference.internal#debug", 1),
			wantValid:  false,
		},
		{
			name:       "present empty backend credential",
			configYAML: strings.Replace(validMinimalYAML, `base_url: "http://127.0.0.1:8000"`, "base_url: \"http://127.0.0.1:8000\"\n  credential: {}", 1),
			wantValid:  false,
		},
		{
			name:       "null backend credential means absent",
			configYAML: strings.Replace(validMinimalYAML, `base_url: "http://127.0.0.1:8000"`, "base_url: \"http://127.0.0.1:8000\"\n  credential: null", 1),
			wantValid:  true,
		},
		{
			name:       "uppercase OIDC scheme",
			configYAML: strings.Replace(validMinimalYAML, "https://idp.example.com", "HTTPS://idp.example.com", 1),
			wantValid:  false,
		},
		{
			name:       "insecure OIDC issuer",
			configYAML: strings.Replace(validMinimalYAML, "https://idp.example.com", "http://idp.example.com", 1),
			wantValid:  false,
		},
		{
			name:       "whitespace audience",
			configYAML: strings.Replace(validMinimalYAML, `audience: "compliant-ai"`, `audience: "   "`, 1),
			wantValid:  false,
		},
		{
			name: "exact duplicate model object",
			configYAML: validMinimalYAML + `  - name: "local-legal"
    backend_model: "qwen-local"
    input_cost_micros_per_million_tokens: 1000
    output_cost_micros_per_million_tokens: 2000
    max_output_tokens: 2048
`,
			wantValid: false,
		},
		{
			name:       "nested unknown field",
			configYAML: strings.Replace(validMinimalYAML, `audience: "compliant-ai"`, "audience: \"compliant-ai\"\n    unexpected: true", 1),
			wantValid:  false,
		},
	}

	schema := compileConfigSchema(t)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var instance any
			if err := yaml.Unmarshal([]byte(tt.configYAML), &instance); err != nil {
				t.Fatalf("decode YAML as schema instance: %v", err)
			}
			schemaErr := schema.Validate(instance)
			_, loaderErr := Load(strings.NewReader(tt.configYAML))

			if got := schemaErr == nil; got != tt.wantValid {
				t.Fatalf("schema valid = %t, want %t: %v", got, tt.wantValid, schemaErr)
			}
			if got := loaderErr == nil; got != tt.wantValid {
				t.Fatalf("loader valid = %t, want %t: %v", got, tt.wantValid, loaderErr)
			}
		})
	}
}

func compileConfigSchema(t *testing.T) *jsonschema.Schema {
	t.Helper()

	encoded, err := os.ReadFile("../../schemas/config-v1.schema.json")
	if err != nil {
		t.Fatalf("read config schema: %v", err)
	}
	var document any
	if err := json.Unmarshal(encoded, &document); err != nil {
		t.Fatalf("parse config schema: %v", err)
	}

	const schemaURL = "https://compliantai.example/schemas/config-v1.schema.json"
	compiler := jsonschema.NewCompiler()
	compiler.AssertFormat()
	if err := compiler.AddResource(schemaURL, document); err != nil {
		t.Fatalf("add config schema: %v", err)
	}
	schema, err := compiler.Compile(schemaURL)
	if err != nil {
		t.Fatalf("compile config schema: %v", err)
	}
	return schema
}
