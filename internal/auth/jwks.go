package auth

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const (
	maxJWKSBodyBytes   = 1 << 20
	maxJWKSKeys        = 64
	minRSAModulusBytes = 256 // 2048-bit minimum
	maxRSAModulusBytes = 512 // 4096-bit maximum
)

var errJWKSRedirectsDisabled = errors.New("jwks redirects disabled")

// JWKSCacheConfig configures a fail-closed JWKS cache.
type JWKSCacheConfig struct {
	URL    string
	TTL    time.Duration
	Client *http.Client
	Now    func() time.Time
}

// JWKSCache fetches and caches issuer signing keys with a hard freshness bound.
type JWKSCache struct {
	url    string
	ttl    time.Duration
	client *http.Client
	now    func() time.Time

	mu sync.Mutex

	keys       map[string]crypto.PublicKey
	fetchedAt  time.Time
	hasCache   bool
	generation uint64

	// forceClaimedGen is the generation for which a force-refresh was claimed
	// (success or failure). Prevents per-request amplification.
	forceClaimedGen uint64
	forceWait       chan struct{}

	ttlWait chan struct{}
}

// NewJWKSCache constructs a JWKS cache bound to one absolute JWKS endpoint.
// Production configuration must supply HTTPS; loopback HTTP is accepted only for tests.
func NewJWKSCache(cfg JWKSCacheConfig) (*JWKSCache, error) {
	if cfg.TTL <= 0 || cfg.Now == nil {
		return nil, ErrAuthenticationUnavailable
	}
	if err := validateJWKSURL(cfg.URL); err != nil {
		return nil, ErrAuthenticationUnavailable
	}
	client, err := jwksHTTPClient(cfg.Client)
	if err != nil {
		return nil, ErrAuthenticationUnavailable
	}
	return &JWKSCache{
		url:    cfg.URL,
		ttl:    cfg.TTL,
		client: client,
		now:    cfg.Now,
		keys:   make(map[string]crypto.PublicKey),
	}, nil
}

func jwksHTTPClient(base *http.Client) (*http.Client, error) {
	var client http.Client
	if base != nil {
		client = *base
	} else {
		client.Timeout = 5 * time.Second
	}
	// Never follow redirects: a compromised IdP must not relocate key material.
	client.CheckRedirect = func(*http.Request, []*http.Request) error {
		return errJWKSRedirectsDisabled
	}
	return &client, nil
}

// PublicKey returns a cached or freshly fetched signing key for kid.
func (cache *JWKSCache) PublicKey(ctx context.Context, kid string) (crypto.PublicKey, error) {
	if cache == nil || cache.client == nil || cache.now == nil || kid == "" || len(kid) > 128 {
		return nil, ErrAuthenticationUnavailable
	}

	for {
		cache.mu.Lock()
		now := cache.now()
		fresh := cache.hasCache && now.Sub(cache.fetchedAt) < cache.ttl

		if fresh {
			if key, ok := cache.keys[kid]; ok {
				cache.mu.Unlock()
				return key, nil
			}

			// Unknown kid while fresh: at most one force-refresh attempt per generation.
			if cache.forceClaimedGen == cache.generation {
				if cache.forceWait != nil {
					wait := cache.forceWait
					cache.mu.Unlock()
					if err := waitFor(ctx, wait); err != nil {
						return nil, err
					}
					continue
				}
				cache.mu.Unlock()
				return nil, ErrUnauthenticated
			}

			claimedGen := cache.generation
			claimedFetchedAt := cache.fetchedAt
			wait := make(chan struct{})
			cache.forceWait = wait
			cache.forceClaimedGen = claimedGen // claim before releasing the lock
			cache.mu.Unlock()

			keys, fetchErr := cache.fetch(ctx)

			cache.mu.Lock()
			close(wait)
			cache.forceWait = nil
			if fetchErr != nil {
				// Keep the claim so this generation does not re-hit the network.
				cache.mu.Unlock()
				return nil, fetchErr
			}
			// Apply only if no newer TTL refresh replaced this generation.
			if cache.generation == claimedGen && cache.fetchedAt.Equal(claimedFetchedAt) {
				cache.keys = keys
				// Do not extend fetchedAt or generation on force-refresh.
			}
			if key, ok := cache.keys[kid]; ok {
				cache.mu.Unlock()
				return key, nil
			}
			cache.mu.Unlock()
			return nil, ErrUnauthenticated
		}

		// Stale or empty cache: singleflight TTL refresh.
		if cache.ttlWait != nil {
			wait := cache.ttlWait
			cache.mu.Unlock()
			if err := waitFor(ctx, wait); err != nil {
				return nil, err
			}
			continue
		}
		priorGen := cache.generation
		wait := make(chan struct{})
		cache.ttlWait = wait
		cache.mu.Unlock()

		keys, fetchErr := cache.fetch(ctx)

		cache.mu.Lock()
		close(wait)
		cache.ttlWait = nil
		if fetchErr != nil {
			cache.mu.Unlock()
			return nil, fetchErr
		}
		if cache.generation == priorGen {
			cache.keys = keys
			cache.fetchedAt = cache.now()
			cache.hasCache = true
			cache.generation = priorGen + 1
			// Fresh generation: force-refresh is available again if a later unknown kid appears.
			// Mark miss on this exact fetch so we do not immediately force-refresh the same set.
			if _, ok := cache.keys[kid]; !ok {
				cache.forceClaimedGen = cache.generation
			}
		}
		if key, ok := cache.keys[kid]; ok {
			cache.mu.Unlock()
			return key, nil
		}
		cache.mu.Unlock()
		return nil, ErrUnauthenticated
	}
}

func waitFor(ctx context.Context, wait <-chan struct{}) error {
	select {
	case <-wait:
		return nil
	case <-ctx.Done():
		return ErrAuthenticationUnavailable
	}
}

func (cache *JWKSCache) fetch(ctx context.Context) (map[string]crypto.PublicKey, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, cache.url, nil)
	if err != nil {
		return nil, ErrAuthenticationUnavailable
	}
	response, err := cache.client.Do(request)
	if err != nil {
		return nil, ErrAuthenticationUnavailable
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, ErrAuthenticationUnavailable
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maxJWKSBodyBytes+1))
	if err != nil || len(body) == 0 || len(body) > maxJWKSBodyBytes {
		return nil, ErrAuthenticationUnavailable
	}
	keys, err := parseJWKS(body)
	if err != nil {
		return nil, ErrAuthenticationUnavailable
	}
	return keys, nil
}

type jwksDocument struct {
	Keys []jwkDocument `json:"keys"`
}

type jwkDocument struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	Use string `json:"use"`
	N   string `json:"n"`
	E   string `json:"e"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

func parseJWKS(body []byte) (map[string]crypto.PublicKey, error) {
	var document jwksDocument
	if err := json.Unmarshal(body, &document); err != nil {
		return nil, err
	}
	if len(document.Keys) > maxJWKSKeys {
		return nil, errors.New("invalid jwks key set")
	}
	keys := make(map[string]crypto.PublicKey, len(document.Keys))
	for _, key := range document.Keys {
		if key.Kid == "" || len(key.Kid) > 128 {
			return nil, errors.New("invalid kid")
		}
		if key.Use != "" && key.Use != "sig" {
			continue
		}
		if _, exists := keys[key.Kid]; exists {
			return nil, errors.New("duplicate kid")
		}
		publicKey, err := parseJWK(key)
		if err != nil {
			if errors.Is(err, errUnsupportedJWK) {
				continue
			}
			return nil, err
		}
		keys[key.Kid] = publicKey
	}
	return keys, nil
}

var errUnsupportedJWK = errors.New("unsupported jwk")

func parseJWK(key jwkDocument) (crypto.PublicKey, error) {
	switch key.Kty {
	case "RSA":
		if key.Alg != "" && key.Alg != "RS256" {
			return nil, errUnsupportedJWK
		}
		modulus, err := decodeJWKBase64(key.N, maxRSAModulusBytes)
		if err != nil {
			return nil, err
		}
		if len(modulus) < minRSAModulusBytes {
			return nil, errors.New("rsa modulus too small")
		}
		exponentBytes, err := decodeJWKBase64(key.E, 8)
		if err != nil {
			return nil, err
		}
		exponentBig := new(big.Int).SetBytes(exponentBytes)
		if !exponentBig.IsInt64() {
			return nil, errors.New("invalid rsa exponent")
		}
		exponent := int(exponentBig.Int64())
		if exponent < 3 || exponent%2 == 0 {
			return nil, errors.New("invalid rsa exponent")
		}
		return &rsa.PublicKey{N: new(big.Int).SetBytes(modulus), E: exponent}, nil
	case "EC":
		if key.Alg != "" && key.Alg != "ES256" {
			return nil, errUnsupportedJWK
		}
		if key.Crv != "P-256" {
			return nil, errUnsupportedJWK
		}
		x, err := decodeJWKBase64(key.X, 32)
		if err != nil {
			return nil, err
		}
		y, err := decodeJWKBase64(key.Y, 32)
		if err != nil {
			return nil, err
		}
		pub := &ecdsa.PublicKey{
			Curve: elliptic.P256(),
			X:     new(big.Int).SetBytes(x),
			Y:     new(big.Int).SetBytes(y),
		}
		if !pub.Curve.IsOnCurve(pub.X, pub.Y) {
			return nil, errors.New("invalid ec point")
		}
		return pub, nil
	default:
		return nil, errUnsupportedJWK
	}
}

func decodeJWKBase64(value string, maxLen int) ([]byte, error) {
	if value == "" {
		return nil, errors.New("missing jwk component")
	}
	raw, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		raw, err = base64.URLEncoding.DecodeString(value)
		if err != nil {
			return nil, err
		}
	}
	if len(raw) == 0 || len(raw) > maxLen {
		return nil, errors.New("invalid jwk component length")
	}
	return raw, nil
}

func validateJWKSURL(raw string) error {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Hostname() == "" {
		return errors.New("invalid jwks url")
	}
	if parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return errors.New("jwks url must not contain credentials, query, or fragment")
	}
	switch {
	case strings.HasPrefix(raw, "https://"):
		return nil
	case strings.HasPrefix(raw, "http://"):
		host := parsed.Hostname()
		if host == "127.0.0.1" || host == "localhost" || host == "::1" {
			return nil
		}
		return errors.New("jwks http url requires loopback host")
	default:
		return errors.New("jwks url must use http or https")
	}
}
