package integration

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/raphbaph/CompliantAI/internal/auth"
	"github.com/raphbaph/CompliantAI/internal/safelog"
)

func TestOIDCAuthentication(t *testing.T) {
	if os.Getenv("TEST_GATEWAY_DSN") == "" || os.Getenv("TEST_SECURITY_ADMIN_DSN") == "" {
		t.Skip("live PostgreSQL test DSNs are not set")
	}
	ctx := context.Background()
	securityAdmin := openTestPool(t, ctx, "TEST_SECURITY_ADMIN_DSN")
	defer securityAdmin.Close()
	gateway := openTestPool(t, ctx, "TEST_GATEWAY_DSN")
	defer gateway.Close()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	jwksServer := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/jwks" {
			http.NotFound(writer, request)
			return
		}
		writer.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(writer).Encode(map[string]any{
			"keys": []map[string]string{integrationRSAJWK(privateKey, "kid-live-1")},
		})
	}))
	defer jwksServer.Close()

	const (
		issuer   = "https://idp.customer.example"
		audience = "compliant-ai-gateway"
	)
	subject := "oidc-auth-" + newTestUUID(t)
	var principalID string
	if err := securityAdmin.QueryRow(ctx,
		`SELECT admin_create_principal($1, $2, $3)`,
		issuer, subject, "OIDC Authentication Fixture",
	).Scan(&principalID); err != nil {
		t.Fatalf("create oidc principal: %v", err)
	}

	now := time.Now().UTC()
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iss":    issuer,
		"aud":    audience,
		"sub":    subject,
		"exp":    now.Add(time.Hour).Unix(),
		"iat":    now.Unix(),
		"groups": []string{"medical-readers", "legal-reviewers"},
		"email":  "JWT-CLAIM-CANARY-should-never-log",
	})
	token.Header["kid"] = "kid-live-1"
	bearer, err := token.SignedString(privateKey)
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}

	store, err := auth.NewPostgresAPIKeyStore(gateway)
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	cache, err := auth.NewJWKSCache(auth.JWKSCacheConfig{
		URL:    jwksServer.URL + "/jwks",
		TTL:    time.Minute,
		Client: jwksServer.Client(),
		Now:    func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("new JWKS cache: %v", err)
	}
	var logOutput bytes.Buffer
	authenticator, err := auth.NewOIDCAuthenticator(auth.OIDCAuthenticatorConfig{
		Issuer:     issuer,
		Audience:   audience,
		GroupClaim: "groups",
		Keys:       cache,
		Store:      store,
		Logger:     safelog.New(&logOutput),
		Now:        func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("new OIDC authenticator: %v", err)
	}

	principal, err := authenticator.AuthenticateOIDC(ctx, bearer)
	if err != nil {
		t.Fatalf("AuthenticateOIDC() error = %v", err)
	}
	if principal.ID != principalID || principal.AuthMethod != auth.AuthMethodOIDC {
		t.Fatalf("principal = %#v", principal)
	}
	if len(principal.Groups) != 2 || principal.Groups[0] != "legal-reviewers" || principal.Groups[1] != "medical-readers" {
		t.Fatalf("groups = %#v", principal.Groups)
	}
	if strings.Contains(logOutput.String(), bearer) || strings.Contains(logOutput.String(), "JWT-CLAIM-CANARY") || strings.Contains(logOutput.String(), subject) {
		t.Fatalf("authentication log leaked token/claim material: %s", logOutput.String())
	}

	unknownToken := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iss": issuer,
		"aud": audience,
		"sub": "missing-" + newTestUUID(t),
		"exp": now.Add(time.Hour).Unix(),
		"iat": now.Unix(),
	})
	unknownToken.Header["kid"] = "kid-live-1"
	unknownBearer, err := unknownToken.SignedString(privateKey)
	if err != nil {
		t.Fatalf("sign unknown token: %v", err)
	}
	if _, err := authenticator.AuthenticateOIDC(ctx, unknownBearer); err != auth.ErrUnauthenticated {
		t.Fatalf("unknown subject error = %v, want ErrUnauthenticated", err)
	}

	if _, err := gateway.Exec(ctx, `SELECT id FROM principals LIMIT 1`); err == nil {
		t.Fatal("gateway_runtime unexpectedly selected from principals")
	}
}

func integrationRSAJWK(privateKey *rsa.PrivateKey, kid string) map[string]string {
	exponent := make([]byte, 8)
	binary.BigEndian.PutUint64(exponent, uint64(privateKey.E))
	for len(exponent) > 1 && exponent[0] == 0 {
		exponent = exponent[1:]
	}
	return map[string]string{
		"kty": "RSA",
		"kid": kid,
		"alg": "RS256",
		"use": "sig",
		"n":   base64.RawURLEncoding.EncodeToString(privateKey.N.Bytes()),
		"e":   base64.RawURLEncoding.EncodeToString(exponent),
	}
}
