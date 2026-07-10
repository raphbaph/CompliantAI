package config

import (
	"errors"
	"fmt"
	"io"

	"gopkg.in/yaml.v3"
)

// Load decodes one gateway configuration from YAML.
func Load(reader io.Reader) (Config, error) {
	var cfg Config
	decoder := yaml.NewDecoder(reader)
	decoder.KnownFields(true)
	if err := decoder.Decode(&cfg); err != nil {
		return Config{}, fmt.Errorf("decode configuration: %w", err)
	}

	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return Config{}, errors.New("decode configuration: exactly one YAML document is required")
	}

	if err := Validate(cfg); err != nil {
		return Config{}, fmt.Errorf("validate configuration: %w", err)
	}
	return cfg, nil
}
