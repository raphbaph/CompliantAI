package integration

import (
	"context"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/raphbaph/CompliantAI/internal/budget"
)

func TestConcurrentBudget(t *testing.T) {
	if os.Getenv("TEST_GATEWAY_DSN") == "" || os.Getenv("TEST_SECURITY_ADMIN_DSN") == "" || os.Getenv("TEST_BOOTSTRAP_DSN") == "" {
		t.Skip("live PostgreSQL test DSNs are not set")
	}
	ctx := context.Background()
	securityAdmin := openTestPool(t, ctx, "TEST_SECURITY_ADMIN_DSN")
	defer securityAdmin.Close()
	gateway := openTestPool(t, ctx, "TEST_GATEWAY_DSN")
	defer gateway.Close()
	bootstrap := openTestPool(t, ctx, "TEST_BOOTSTRAP_DSN")
	defer bootstrap.Close()

	service, err := budget.NewService(gateway)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}

	principalID := createBudgetedPrincipal(t, ctx, securityAdmin, "budget-basic")
	reservation, err := service.Reserve(ctx, budget.ReserveRequest{
		PrincipalID:       principalID,
		RunID:             newTestUUID(t),
		ModelName:         "local-legal",
		ReservedMaxMicros: 400,
		TTL:               time.Minute,
	})
	if err != nil {
		t.Fatalf("reserve: %v", err)
	}
	actual := int64(250)
	settled, err := service.Settle(ctx, budget.SettleRequest{ReservationID: reservation.ID, ActualMicros: &actual})
	if err != nil || settled != 250 {
		t.Fatalf("settle = %d err=%v", settled, err)
	}
	assertBudgetAccount(t, ctx, gateway, principalID, 250, 0)

	reservation2, err := service.Reserve(ctx, budget.ReserveRequest{
		PrincipalID:       principalID,
		RunID:             newTestUUID(t),
		ModelName:         "local-legal",
		ReservedMaxMicros: 300,
		TTL:               time.Minute,
	})
	if err != nil {
		t.Fatalf("reserve2: %v", err)
	}
	settled2, err := service.Settle(ctx, budget.SettleRequest{ReservationID: reservation2.ID, ActualMicros: nil})
	if err != nil || settled2 != 300 {
		t.Fatalf("conservative settle = %d err=%v", settled2, err)
	}
	assertBudgetAccount(t, ctx, gateway, principalID, 550, 0)

	_, err = service.Reserve(ctx, budget.ReserveRequest{
		PrincipalID:       principalID,
		RunID:             newTestUUID(t),
		ModelName:         "local-legal",
		ReservedMaxMicros: 500,
		TTL:               time.Minute,
	})
	if err != budget.ErrBudgetDenied {
		t.Fatalf("over-limit error = %v, want ErrBudgetDenied", err)
	}

	racePrincipal := createBudgetedPrincipal(t, ctx, securityAdmin, "budget-race")
	const dailyLimit int64 = 1_000
	const workers = 20
	const each int64 = 100
	var accepted atomic.Int64
	var denied atomic.Int64
	start := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go func() {
			defer wg.Done()
			<-start
			_, err := service.Reserve(ctx, budget.ReserveRequest{
				PrincipalID:       racePrincipal,
				RunID:             newTestUUID(t),
				ModelName:         "local-legal",
				ReservedMaxMicros: each,
				TTL:               time.Minute,
			})
			switch err {
			case nil:
				accepted.Add(1)
			case budget.ErrBudgetDenied:
				denied.Add(1)
			default:
				t.Errorf("reserve error: %v", err)
			}
		}()
	}
	close(start)
	wg.Wait()
	if accepted.Load() != 10 || denied.Load() != 10 {
		t.Fatalf("accepted=%d denied=%d, want 10/10", accepted.Load(), denied.Load())
	}
	assertBudgetAccount(t, ctx, gateway, racePrincipal, 0, dailyLimit)

	disabledPrincipal := createBudgetedPrincipal(t, ctx, securityAdmin, "budget-disabled")
	if _, err := bootstrap.Exec(ctx,
		`UPDATE principals SET status = 'disabled', disabled_at = statement_timestamp() WHERE id = $1::uuid`, disabledPrincipal,
	); err != nil {
		t.Fatalf("disable principal: %v", err)
	}
	_, err = service.Reserve(ctx, budget.ReserveRequest{
		PrincipalID:       disabledPrincipal,
		RunID:             newTestUUID(t),
		ModelName:         "local-legal",
		ReservedMaxMicros: 100,
		TTL:               time.Minute,
	})
	if err != budget.ErrBudgetDenied {
		t.Fatalf("disabled reserve error = %v, want ErrBudgetDenied", err)
	}

	expirePrincipal := createBudgetedPrincipal(t, ctx, securityAdmin, "budget-expire")
	res, err := service.Reserve(ctx, budget.ReserveRequest{
		PrincipalID:       expirePrincipal,
		RunID:             newTestUUID(t),
		ModelName:         "local-legal",
		ReservedMaxMicros: 200,
		TTL:               time.Minute,
	})
	if err != nil {
		t.Fatalf("reserve expire case: %v", err)
	}
	if _, err := bootstrap.Exec(ctx,
		`UPDATE spend_reservations
		 SET created_at = statement_timestamp() - interval '2 seconds',
		     expires_at = statement_timestamp() - interval '1 second'
		 WHERE id = $1::uuid`, res.ID,
	); err != nil {
		t.Fatalf("force expiry: %v", err)
	}
	expired, err := service.ExpireReservations(ctx)
	if err != nil {
		t.Fatalf("ExpireReservations: %v", err)
	}
	if expired < 1 {
		t.Fatalf("expired count = %d", expired)
	}
	assertBudgetAccount(t, ctx, gateway, expirePrincipal, 0, 0)

	_, err = gateway.Exec(ctx, `UPDATE budget_accounts SET daily_reserved_micros = 0 WHERE principal_id = $1`, racePrincipal)
	assertSQLState(t, err, "42501")
}

func createBudgetedPrincipal(t *testing.T, ctx context.Context, securityAdmin *pgxpool.Pool, label string) string {
	t.Helper()
	var principalID string
	if err := securityAdmin.QueryRow(ctx,
		`SELECT admin_create_principal($1, $2, $3)`,
		"https://idp.customer.example", fmt.Sprintf("%s-%d", label, time.Now().UnixNano()), label,
	).Scan(&principalID); err != nil {
		t.Fatalf("create principal: %v", err)
	}
	if _, err := securityAdmin.Exec(ctx, `SELECT admin_set_budget($1, $2, $3)`, principalID, int64(1_000), int64(10_000)); err != nil {
		t.Fatalf("set budget: %v", err)
	}
	return principalID
}

func assertBudgetAccount(t *testing.T, ctx context.Context, gateway *pgxpool.Pool, principalID string, wantCommitted, wantReserved int64) {
	t.Helper()
	var committed, reserved int64
	if err := gateway.QueryRow(ctx,
		`SELECT daily_committed_micros, daily_reserved_micros FROM budget_accounts WHERE principal_id = $1`, principalID,
	).Scan(&committed, &reserved); err != nil {
		t.Fatalf("read account: %v", err)
	}
	if committed != wantCommitted || reserved != wantReserved {
		t.Fatalf("account committed/reserved = %d/%d, want %d/%d", committed, reserved, wantCommitted, wantReserved)
	}
}
