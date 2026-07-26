package budget

import "time"

// ReservationState is the durable reservation lifecycle state.
type ReservationState string

const (
	StateReserved ReservationState = "reserved"
	StateSettled  ReservationState = "settled"
	StateReleased ReservationState = "released"
	StateExpired  ReservationState = "expired"
)

// Reservation is the content-free spend hold created before backend invocation.
type Reservation struct {
	ID                 string
	RunID              string
	PrincipalID        string
	ModelName          string
	ReservedMaxMicros  int64
	SettledActualMicros *int64
	State              ReservationState
	ExpiresAt          time.Time
}

// ReserveRequest is the content-free reservation input.
type ReserveRequest struct {
	PrincipalID       string
	RunID             string
	ModelName         string
	ReservedMaxMicros int64
	TTL               time.Duration
}

// SettleRequest finalizes a reservation after backend usage is known.
// If ActualMicros is nil, settlement uses the conservative reserved maximum.
type SettleRequest struct {
	ReservationID string
	ActualMicros  *int64
}
