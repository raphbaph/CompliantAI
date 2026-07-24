package store

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5/pgxpool"
)

// ErrConnect is returned for every configuration or connectivity failure.
var ErrConnect = errors.New("postgres connection failed")

// Open creates and verifies a PostgreSQL connection pool without exposing DSN details.
func Open(ctx context.Context, dsn string) (*pgxpool.Pool, error) {
	config, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, ErrConnect
	}
	config.ConnConfig.RuntimeParams["application_name"] = "compliantai-gateway"

	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		return nil, ErrConnect
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, ErrConnect
	}
	return pool, nil
}
