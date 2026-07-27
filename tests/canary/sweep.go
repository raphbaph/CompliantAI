package canary

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"
)

// Canaries holds unique high-entropy markers used once per test run.
type Canaries struct {
	Prompt       string
	Response     string
	APIKey       string
	JWTClaim     string
	Malformed    string
	BackendError string
}

// NewCanaries generates distinct markers that are unlikely to collide with fixtures.
func NewCanaries() (Canaries, error) {
	mk := func(label string) (string, error) {
		var raw [24]byte
		if _, err := rand.Read(raw[:]); err != nil {
			return "", err
		}
		return fmt.Sprintf("CANARY-%s-%s", label, hex.EncodeToString(raw[:])), nil
	}
	prompt, err := mk("PROMPT")
	if err != nil {
		return Canaries{}, err
	}
	response, err := mk("RESPONSE")
	if err != nil {
		return Canaries{}, err
	}
	apiKey, err := mk("APIKEY")
	if err != nil {
		return Canaries{}, err
	}
	jwtClaim, err := mk("JWTCLAIM")
	if err != nil {
		return Canaries{}, err
	}
	malformed, err := mk("MALFORMED")
	if err != nil {
		return Canaries{}, err
	}
	backendError, err := mk("BACKENDERR")
	if err != nil {
		return Canaries{}, err
	}
	return Canaries{
		Prompt:       prompt,
		Response:     response,
		APIKey:       apiKey,
		JWTClaim:     jwtClaim,
		Malformed:    malformed,
		BackendError: backendError,
	}, nil
}

// All returns every canary string for sweep searches.
func (c Canaries) All() []string {
	return []string{c.Prompt, c.Response, c.APIKey, c.JWTClaim, c.Malformed, c.BackendError}
}

// Report records exactly which locations and encodings were searched.
type Report struct {
	PathsExercised []string `json:"paths_exercised"`
	Locations      []string `json:"locations_searched"`
	Encodings      []string `json:"encodings_searched"`
	Canaries       []string `json:"canaries"`
	Findings       []string `json:"findings"`
}

// ValidWording is the only approved positive claim for a clean sweep.
const ValidWording = "No tested canary was detected in the enumerated persistence locations."

// NoteFinding records a canary hit with location context (never surrounding content).
func (r *Report) NoteFinding(location, canary string) {
	r.Findings = append(r.Findings, fmt.Sprintf("%s contains canary %s", location, canary))
}

// AddLocation records a location only after it is actually searched.
func (r *Report) AddLocation(name string) {
	r.Locations = append(r.Locations, name)
}

// SearchBytes looks for exact and case-folded UTF-8 canary substrings.
func SearchBytes(data []byte, canaries []string) []string {
	if len(data) == 0 {
		return nil
	}
	return SearchText(string(data), canaries)
}

// SearchText looks for exact and case-folded UTF-8 canary substrings.
func SearchText(text string, canaries []string) []string {
	var hits []string
	lowerText := strings.ToLower(text)
	for _, canary := range canaries {
		if canary == "" {
			continue
		}
		if strings.Contains(text, canary) || strings.Contains(lowerText, strings.ToLower(canary)) {
			hits = append(hits, canary)
		}
	}
	return hits
}

// SearchDir walks a directory tree and searches regular file contents.
func SearchDir(root string, canaries []string, maxFiles int) (hits map[string][]string, filesScanned int, err error) {
	hits = map[string][]string{}
	if root == "" {
		return hits, 0, nil
	}
	err = filepath.Walk(root, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if info.IsDir() {
			return nil
		}
		if maxFiles > 0 && filesScanned >= maxFiles {
			return filepath.SkipAll
		}
		switch strings.ToLower(filepath.Ext(path)) {
		case ".png", ".jpg", ".jpeg", ".gif", ".woff", ".woff2", ".exe", ".so", ".dylib":
			return nil
		}
		if info.Size() > 8<<20 {
			return nil
		}
		raw, readErr := os.ReadFile(path)
		if readErr != nil {
			return nil
		}
		if !utf8.Valid(raw) && looksBinary(raw) {
			return nil
		}
		filesScanned++
		if found := SearchBytes(raw, canaries); len(found) > 0 {
			hits[path] = found
		}
		return nil
	})
	if err == filepath.SkipAll {
		err = nil
	}
	return hits, filesScanned, err
}

func looksBinary(raw []byte) bool {
	n := len(raw)
	if n > 512 {
		n = 512
	}
	for i := 0; i < n; i++ {
		if raw[i] == 0 {
			return true
		}
	}
	return false
}

// DefaultEncodings documents encodings actually implemented by SearchText/SearchBytes.
func DefaultEncodings() []string {
	return []string{
		"utf-8 exact substring",
		"utf-8 case-folded substring",
	}
}
