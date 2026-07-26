package budget

import (
	"context"
	"errors"
	"regexp"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	reserveBudgetSQL = `SELECT reservation_id::text FROM reserve_budget($1::uuid, $2::uuid, $3::text, $4::bigint, $5::integer)`
	settleBudgetSQL  = `SELECT settled_actual_micros FROM settle_budget($1::uuid, $2::bigint)`
	expireBudgetSQL  = `SELECT expire_budget_reservations()`
)

var (
	uuidPattern  = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	modelPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
)

// Service performs atomic per-principal budget reservation and settlement.
type Service struct {
	pool *pgxpool.Pool
}

// NewService binds budget operations to a role-scoped pool.
func NewService(pool *pgxpool.Pool) (*Service, error) {
	if pool == nil {
		return nil, ErrBudgetUnavailable
	}
	return &Service{pool: pool}, nil
}

// Reserve atomically holds budget for a run if principal and remaining limits allow it.
func (service *Service) Reserve(ctx context.Context, request ReserveRequest) (Reservation, error) {
	if service == nil || service.pool == nil {
		return Reservation{}, ErrBudgetUnavailable
	}
	if !uuidPattern.MatchString(request.PrincipalID) || !uuidPattern.MatchString(request.RunID) ||
		!modelPattern.MatchString(request.ModelName) || request.ReservedMaxMicros <= 0 {
		return Reservation{}, ErrInvalidReservation
	}
	ttlSeconds := int(request.TTL / time.Second)
	if request.TTL <= 0 || ttlSeconds <= 0 || ttlSeconds > 86400 {
		return Reservation{}, ErrInvalidReservation
	}

	var reservationID string
	err := service.pool.QueryRow(ctx, reserveBudgetSQL,
		request.PrincipalID,
		request.RunID,
		request.ModelName,
		request.ReservedMaxMicros,
		ttlSeconds,
	).Scan(&reservationID)
	if err != nil {
		return Reservation{}, mapBudgetError(err)
	}
	if !uuidPattern.MatchString(reservationID) {
		return Reservation{}, ErrBudgetUnavailable
	}
	return Reservation{
		ID:                reservationID,
		RunID:             request.RunID,
		PrincipalID:       request.PrincipalID,
		ModelName:         request.ModelName,
		ReservedMaxMicros: request.ReservedMaxMicros,
		State:             StateReserved,
		ExpiresAt:         time.Now().UTC().Add(time.Duration(ttlSeconds) * time.Second),
	}, nil
}

// Settle finalizes a reserved hold. Nil ActualMicros settles conservatively to the reserved max.
func (service *Service) Settle(ctx context.Context, request SettleRequest) (int64, error) {
	if service == nil || service.pool == nil {
		return 0, ErrBudgetUnavailable
	}
	if !uuidPattern.MatchString(request.ReservationID) {
		return 0, ErrInvalidReservation
	}
	var actualArg any
	if request.ActualMicros == nil {
		actualArg = nil
	} else {
		if *request.ActualMicros < 0 {
			return 0, ErrInvalidReservation
		}
		actualArg = *request.ActualMicros
	}
	var settled int64
	err := service.pool.QueryRow(ctx, settleBudgetSQL, request.ReservationID, actualArg).Scan(&settled)
	if err != nil {
		return 0, mapBudgetError(err)
	}
	if settled < 0 {
		return 0, ErrBudgetUnavailable
	}
	return settled, nil
}

// ExpireReservations recovers expired holds and returns how many were expired.
func (service *Service) ExpireReservations(ctx context.Context) (int64, error) {
	if service == nil || service.pool == nil {
		return 0, ErrBudgetUnavailable
	}
	var expired int64
	if err := service.pool.QueryRow(ctx, expireBudgetSQL).Scan(&expired); err != nil {
		return 0, ErrBudgetUnavailable
	}
	if expired < 0 {
		return 0, ErrBudgetUnavailable
	}
	return expired, nil
}

func mapBudgetError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrBudgetNotFound
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		switch pgErr.Message {
		case "budget denied":
			return ErrBudgetDenied
		case "budget reservation not found":
			return ErrBudgetNotFound
		case "invalid budget reservation":
			return ErrInvalidReservation
		}
	}
	return ErrBudgetUnavailable
}
