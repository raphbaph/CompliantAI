package store

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestOpenFailureDoesNotRevealDSN(t *testing.T) {
	const passwordCanary = "DATABASE-PASSWORD-CANARY"
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	dsn := (&url.URL{
		Scheme:   "postgres",
		User:     url.UserPassword("gateway_runtime", passwordCanary),
		Host:     "127.0.0.1:1",
		Path:     "/compliantai",
		RawQuery: "sslmode=disable",
	}).String()
	pool, err := Open(ctx, dsn)
	if pool != nil {
		pool.Close()
		t.Fatal("Open() pool is non-nil on connection failure")
	}
	if !errors.Is(err, ErrConnect) {
		t.Fatalf("Open() error = %v, want ErrConnect", err)
	}
	if strings.Contains(err.Error(), passwordCanary) {
		t.Fatalf("Open() error reveals DSN credential: %v", err)
	}
}
