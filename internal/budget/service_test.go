package budget_test

import (
	"context"
	"testing"
	"time"

	"github.com/raphbaph/CompliantAI/internal/budget"
)

func TestServiceNilPoolAndNilServiceFailClosed(t *testing.T) {
	if _, err := budget.NewService(nil); err != budget.ErrBudgetUnavailable {
		t.Fatalf("NewService(nil) error = %v", err)
	}
	var service *budget.Service
	_, err := service.Reserve(context.Background(), budget.ReserveRequest{
		PrincipalID:       "00000000-0000-4000-8000-000000000001",
		RunID:             "00000000-0000-4000-8000-000000000002",
		ModelName:         "local-legal",
		ReservedMaxMicros: 100,
		TTL:               time.Minute,
	})
	if err != budget.ErrBudgetUnavailable {
		t.Fatalf("nil service Reserve error = %v", err)
	}
}

func TestServiceRejectsInvalidReserveShape(t *testing.T) {
	// Zero-value service has nil pool; validation still fails closed as unavailable.
	service := &budget.Service{}
	_, err := service.Reserve(context.Background(), budget.ReserveRequest{
		PrincipalID:       "bad",
		RunID:             "00000000-0000-4000-8000-000000000002",
		ModelName:         "local-legal",
		ReservedMaxMicros: 100,
		TTL:               time.Minute,
	})
	if err != budget.ErrBudgetUnavailable && err != budget.ErrInvalidReservation {
		t.Fatalf("invalid reserve error = %v", err)
	}
}
