package backend

import "errors"

// Fixed content-free backend errors. Public messages never include upstream bodies.
var (
	ErrInvalidRequest    = errors.New("backend request invalid")
	ErrTimeout           = errors.New("backend timeout")
	ErrUnavailable       = errors.New("backend unavailable")
	ErrInvalidResponse   = errors.New("backend invalid response")
	ErrResponseTooLarge  = errors.New("backend response too large")
	ErrUsageInvalid      = errors.New("backend usage invalid")
	ErrInvalidConfig     = errors.New("backend configuration invalid")
)

// Code maps a backend error to the operational fixed code label.
func Code(err error) string {
	switch {
	case errors.Is(err, ErrTimeout):
		return "timeout"
	case errors.Is(err, ErrUnavailable):
		return "unavailable"
	case errors.Is(err, ErrInvalidResponse), errors.Is(err, ErrInvalidRequest):
		return "invalid_response"
	case errors.Is(err, ErrResponseTooLarge):
		return "response_too_large"
	case errors.Is(err, ErrUsageInvalid):
		return "usage_invalid"
	default:
		return "unavailable"
	}
}
