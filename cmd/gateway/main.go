package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/raphbaph/CompliantAI/internal/version"
)

func main() {
	showVersion := flag.Bool("version", false, "print build metadata as JSON")
	configPath := flag.String("config", "", "path to gateway configuration YAML (server wiring lands with full deployment bootstrap)")
	flag.Parse()

	if *showVersion {
		if err := json.NewEncoder(os.Stdout).Encode(version.Current()); err != nil {
			fmt.Fprintln(os.Stderr, "failed to encode build metadata")
			os.Exit(1)
		}
		return
	}

	if *configPath != "" {
		// Full process bootstrap (TLS, DB pools, OIDC/JWKS, secrets) is assembled in
		// deployment follow-up. The HTTP vertical slice lives in internal/api and is
		// covered by package tests with injected collaborators.
		fmt.Fprintln(os.Stderr, "gateway process bootstrap is not fully wired; use internal/api tests for the vertical slice")
		os.Exit(2)
	}

	fmt.Fprintln(os.Stderr, "usage: gateway --version | --config PATH")
	os.Exit(2)
}
