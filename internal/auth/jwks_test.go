package auth

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestJWKSCacheServesFreshKeysAndRespectsTTL(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	var fetches atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		fetches.Add(1)
		if request.Method != http.MethodGet || request.URL.Path != "/jwks" {
			http.NotFound(writer, request)
			return
		}
		writer.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(writer).Encode(map[string]any{
			"keys": []map[string]string{rsaJWK(privateKey, "kid-1")},
		})
	}))
	defer server.Close()

	now := time.Date(2026, time.July, 26, 12, 0, 0, 0, time.UTC)
	cache, err := NewJWKSCache(JWKSCacheConfig{
		URL:    server.URL + "/jwks",
		TTL:    time.Minute,
		Client: server.Client(),
		Now:    func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("NewJWKSCache() error = %v", err)
	}

	key, err := cache.PublicKey(t.Context(), "kid-1")
	if err != nil {
		t.Fatalf("PublicKey() error = %v", err)
	}
	if key == nil {
		t.Fatal("PublicKey() returned nil key")
	}
	if _, err := cache.PublicKey(t.Context(), "kid-1"); err != nil {
		t.Fatalf("cached PublicKey() error = %v", err)
	}
	if got := fetches.Load(); got != 1 {
		t.Fatalf("JWKS fetches = %d, want 1 while cache is fresh", got)
	}

	now = now.Add(time.Minute + time.Second)
	if _, err := cache.PublicKey(t.Context(), "kid-1"); err != nil {
		t.Fatalf("refresh PublicKey() error = %v", err)
	}
	if got := fetches.Load(); got != 2 {
		t.Fatalf("JWKS fetches = %d, want 2 after TTL expiry", got)
	}
}

func TestJWKSCacheFailsClosedForUnknownKidAndUnavailableIdP(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	var mode atomic.Int32 // 0 = known key, 1 = empty set, 2 = 503
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		switch mode.Load() {
		case 1:
			writer.Header().Set("Content-Type", "application/json")
			_, _ = writer.Write([]byte(`{"keys":[]}`))
		case 2:
			http.Error(writer, "unavailable", http.StatusServiceUnavailable)
		default:
			writer.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(writer).Encode(map[string]any{
				"keys": []map[string]string{rsaJWK(privateKey, "kid-1")},
			})
		}
	}))
	defer server.Close()

	now := time.Date(2026, time.July, 26, 12, 0, 0, 0, time.UTC)
	cache, err := NewJWKSCache(JWKSCacheConfig{
		URL:    server.URL + "/jwks",
		TTL:    time.Minute,
		Client: server.Client(),
		Now:    func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("NewJWKSCache() error = %v", err)
	}
	if _, err := cache.PublicKey(t.Context(), "kid-1"); err != nil {
		t.Fatalf("seed PublicKey() error = %v", err)
	}

	if _, err := cache.PublicKey(t.Context(), "missing-kid"); err != ErrUnauthenticated {
		t.Fatalf("unknown kid while fresh error = %v, want ErrUnauthenticated", err)
	}

	mode.Store(2)
	now = now.Add(time.Minute + time.Second)
	if _, err := cache.PublicKey(t.Context(), "kid-1"); err != ErrAuthenticationUnavailable {
		t.Fatalf("expired cache with unavailable IdP error = %v, want ErrAuthenticationUnavailable", err)
	}

	mode.Store(1)
	if _, err := cache.PublicKey(t.Context(), "kid-1"); err != ErrUnauthenticated {
		t.Fatalf("refreshed empty JWKS error = %v, want ErrUnauthenticated", err)
	}
}

func TestJWKSCacheUnknownKidPerformsOnlyOneRefreshWhileFresh(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	var fetches atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		fetches.Add(1)
		writer.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(writer).Encode(map[string]any{
			"keys": []map[string]string{rsaJWK(privateKey, "kid-1")},
		})
	}))
	defer server.Close()

	now := time.Date(2026, time.July, 26, 12, 0, 0, 0, time.UTC)
	cache, err := NewJWKSCache(JWKSCacheConfig{
		URL:    server.URL + "/jwks",
		TTL:    time.Minute,
		Client: server.Client(),
		Now:    func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("NewJWKSCache() error = %v", err)
	}
	if _, err := cache.PublicKey(t.Context(), "kid-1"); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if got := fetches.Load(); got != 1 {
		t.Fatalf("fetches after seed = %d", got)
	}
	for i := 0; i < 3; i++ {
		if _, err := cache.PublicKey(t.Context(), "missing-a"); err != ErrUnauthenticated {
			t.Fatalf("missing-a lookup %d: %v", i, err)
		}
		if _, err := cache.PublicKey(t.Context(), "missing-b"); err != ErrUnauthenticated {
			t.Fatalf("missing-b lookup %d: %v", i, err)
		}
	}
	if got := fetches.Load(); got != 2 {
		t.Fatalf("JWKS fetches = %d, want exactly one force refresh while fresh", got)
	}
	// Force-refresh must not extend freshness window.
	now = now.Add(30 * time.Second)
	if _, err := cache.PublicKey(t.Context(), "kid-1"); err != nil {
		t.Fatalf("still-fresh known key: %v", err)
	}
	if got := fetches.Load(); got != 2 {
		t.Fatalf("known key after force-refresh extended TTL: fetches=%d", got)
	}
}

func TestJWKSCacheConcurrentUnknownKidsSingleForceRefresh(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	var fetches atomic.Int32
	started := make(chan struct{})
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		n := fetches.Add(1)
		if n >= 2 {
			// Block force-refresh so concurrent waiters pile up.
			close(started)
			<-release
		}
		writer.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(writer).Encode(map[string]any{
			"keys": []map[string]string{rsaJWK(privateKey, "kid-1")},
		})
	}))
	defer server.Close()

	now := time.Date(2026, time.July, 26, 12, 0, 0, 0, time.UTC)
	cache, err := NewJWKSCache(JWKSCacheConfig{
		URL:    server.URL + "/jwks",
		TTL:    time.Minute,
		Client: server.Client(),
		Now:    func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("NewJWKSCache() error = %v", err)
	}
	if _, err := cache.PublicKey(t.Context(), "kid-1"); err != nil {
		t.Fatalf("seed: %v", err)
	}

	const workers = 16
	errCh := make(chan error, workers)
	var ready sync.WaitGroup
	ready.Add(workers)
	start := make(chan struct{})
	for i := 0; i < workers; i++ {
		go func(i int) {
			ready.Done()
			<-start
			_, err := cache.PublicKey(t.Context(), "missing-"+string(rune('a'+i%26)))
			errCh <- err
		}(i)
	}
	ready.Wait()
	close(start)
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("force refresh did not start")
	}
	// While one force-refresh is in flight, no additional fetches should start.
	time.Sleep(50 * time.Millisecond)
	if got := fetches.Load(); got != 2 {
		t.Fatalf("in-flight fetches = %d, want 2 (seed + one force)", got)
	}
	close(release)
	for i := 0; i < workers; i++ {
		if err := <-errCh; err != ErrUnauthenticated {
			t.Fatalf("worker error = %v, want ErrUnauthenticated", err)
		}
	}
	if got := fetches.Load(); got != 2 {
		t.Fatalf("final fetches = %d, want 2", got)
	}
}

func TestJWKSCacheForceRefreshFailureDoesNotRetrigger(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	var fetches atomic.Int32
	var mode atomic.Int32 // 0 ok, 1 fail
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		fetches.Add(1)
		if mode.Load() == 1 {
			http.Error(writer, "boom", http.StatusServiceUnavailable)
			return
		}
		writer.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(writer).Encode(map[string]any{
			"keys": []map[string]string{rsaJWK(privateKey, "kid-1")},
		})
	}))
	defer server.Close()

	now := time.Date(2026, time.July, 26, 12, 0, 0, 0, time.UTC)
	cache, err := NewJWKSCache(JWKSCacheConfig{
		URL:    server.URL + "/jwks",
		TTL:    time.Minute,
		Client: server.Client(),
		Now:    func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("NewJWKSCache() error = %v", err)
	}
	if _, err := cache.PublicKey(t.Context(), "kid-1"); err != nil {
		t.Fatalf("seed: %v", err)
	}
	mode.Store(1)
	if _, err := cache.PublicKey(t.Context(), "missing"); err != ErrAuthenticationUnavailable {
		t.Fatalf("first force failure = %v", err)
	}
	if _, err := cache.PublicKey(t.Context(), "missing-again"); err != ErrUnauthenticated {
		t.Fatalf("second unknown after failed force = %v, want ErrUnauthenticated without re-fetch", err)
	}
	if got := fetches.Load(); got != 2 {
		t.Fatalf("fetches = %d, want 2", got)
	}
}

func TestJWKSCacheRejectsRedirects(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	var finalHits atomic.Int32
	final := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		finalHits.Add(1)
		writer.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(writer).Encode(map[string]any{
			"keys": []map[string]string{rsaJWK(privateKey, "kid-1")},
		})
	}))
	defer final.Close()
	redirector := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		http.Redirect(writer, request, final.URL+"/jwks", http.StatusFound)
	}))
	defer redirector.Close()

	cache, err := NewJWKSCache(JWKSCacheConfig{
		URL:    redirector.URL + "/jwks",
		TTL:    time.Minute,
		Client: redirector.Client(),
		Now:    func() time.Time { return time.Date(2026, time.July, 26, 12, 0, 0, 0, time.UTC) },
	})
	if err != nil {
		t.Fatalf("NewJWKSCache() error = %v", err)
	}
	if _, err := cache.PublicKey(t.Context(), "kid-1"); err != ErrAuthenticationUnavailable {
		t.Fatalf("redirecting JWKS error = %v, want ErrAuthenticationUnavailable", err)
	}
	if finalHits.Load() != 0 {
		t.Fatalf("redirect target was contacted %d times", finalHits.Load())
	}
}

func TestParseJWKSRejectsWeakRSAModulus(t *testing.T) {
	weakN := base64.RawURLEncoding.EncodeToString(big.NewInt(65537).Bytes()) // tiny modulus
	body, _ := json.Marshal(map[string]any{
		"keys": []map[string]string{{
			"kty": "RSA",
			"kid": "weak",
			"alg": "RS256",
			"use": "sig",
			"n":   weakN,
			"e":   base64.RawURLEncoding.EncodeToString(bigEndianInt(65537)),
		}},
	})
	keys, err := parseJWKS(body)
	if err != nil {
		// Either fail parse or yield empty usable set.
		return
	}
	if _, ok := keys["weak"]; ok {
		t.Fatal("weak RSA modulus was accepted")
	}
}

func rsaJWK(privateKey *rsa.PrivateKey, kid string) map[string]string {
	return map[string]string{
		"kty": "RSA",
		"kid": kid,
		"alg": "RS256",
		"use": "sig",
		"n":   base64.RawURLEncoding.EncodeToString(privateKey.N.Bytes()),
		"e":   base64.RawURLEncoding.EncodeToString(bigEndianInt(privateKey.E)),
	}
}

func bigEndianInt(value int) []byte {
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, uint64(value))
	trimmed := buf
	for len(trimmed) > 1 && trimmed[0] == 0 {
		trimmed = trimmed[1:]
	}
	return trimmed
}
