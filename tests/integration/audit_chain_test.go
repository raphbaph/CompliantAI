package integration

import (
	"context"
	"crypto/rand"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/raphbaph/CompliantAI/internal/audit"
)

func TestAuditChain(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	for _, envName := range []string{"TEST_BOOTSTRAP_DSN", "TEST_GATEWAY_DSN", "TEST_AUDIT_READER_DSN", "TEST_SECURITY_ADMIN_DSN"} {
		if testEnvironmentValue(t, envName) == "" {
			t.Skipf("%s is not set", envName)
		}
	}

	bootstrap := openTestPool(t, ctx, "TEST_BOOTSTRAP_DSN")
	defer bootstrap.Close()
	gateway := openTestPool(t, ctx, "TEST_GATEWAY_DSN")
	defer gateway.Close()
	reader := openTestPool(t, ctx, "TEST_AUDIT_READER_DSN")
	defer reader.Close()
	securityAdmin := openTestPool(t, ctx, "TEST_SECURITY_ADMIN_DSN")
	defer securityAdmin.Close()

	var principalID string
	if err := securityAdmin.QueryRow(ctx,
		`SELECT admin_create_principal($1, $2, $3)`,
		"https://idp.customer.example", "audit-chain-"+newTestUUID(t), "integration-fixture",
	).Scan(&principalID); err != nil {
		t.Fatalf("create chain principal: %v", err)
	}
	for identifierType, identifierValue := range map[string]string{
		"model":            "chain-model",
		"backend":          "chain-backend",
		"software_version": "chain-integration",
		"content_hmac_key": "chain-content-key-v1",
	} {
		if _, err := securityAdmin.Exec(ctx,
			`SELECT admin_register_audit_identifier($1, $2)`, identifierType, identifierValue,
		); err != nil {
			t.Fatalf("register %s: %v", identifierType, err)
		}
	}

	writer, err := audit.NewRepository(gateway)
	if err != nil {
		t.Fatalf("audit.NewRepository(gateway): %v", err)
	}
	verifier, err := audit.NewRepository(reader)
	if err != nil {
		t.Fatalf("audit.NewRepository(reader): %v", err)
	}

	var initialSequence int64
	if err := bootstrap.QueryRow(ctx, `SELECT sequence FROM audit_chain_head WHERE singleton`).Scan(&initialSequence); err != nil {
		t.Fatalf("read initial chain head: %v", err)
	}

	failedEvent := chainEventFixture(t, principalID)
	failedEvent.RequestedModel = "unregistered-chain-model"
	failedReceipt, err := writer.Append(ctx, failedEvent)
	if err == nil {
		t.Fatal("unregistered model append succeeded")
	}
	if failedReceipt.AuthorizesBackendCall() {
		t.Fatal("failed database write produced backend authorization")
	}
	var sequenceAfterFailure int64
	if err := bootstrap.QueryRow(ctx, `SELECT sequence FROM audit_chain_head WHERE singleton`).Scan(&sequenceAfterFailure); err != nil {
		t.Fatalf("read chain head after failure: %v", err)
	}
	if sequenceAfterFailure != initialSequence {
		t.Fatalf("failed append advanced chain head to %d, want %d", sequenceAfterFailure, initialSequence)
	}

	duplicateEvent := chainEventFixture(t, principalID)
	committedReceipt, err := writer.Append(ctx, duplicateEvent)
	if err != nil {
		t.Fatalf("seed duplicate-event probe: %v", err)
	}
	if !committedReceipt.AuthorizesBackendCall() {
		t.Fatal("committed duplicate-event seed did not authorize backend")
	}
	initialSequence = committedReceipt.Sequence()
	duplicateReceipt, err := writer.Append(ctx, duplicateEvent)
	if err == nil {
		t.Fatal("duplicate event ID append succeeded")
	}
	if duplicateReceipt.AuthorizesBackendCall() {
		t.Fatal("rolled-back duplicate append produced backend authorization")
	}
	var sequenceAfterRollback int64
	if err := bootstrap.QueryRow(ctx, `SELECT sequence FROM audit_chain_head WHERE singleton`).Scan(&sequenceAfterRollback); err != nil {
		t.Fatalf("read chain head after duplicate rollback: %v", err)
	}
	if sequenceAfterRollback != initialSequence {
		t.Fatalf("rolled-back append advanced chain head to %d, want %d", sequenceAfterRollback, initialSequence)
	}

	const concurrentEvents = 16
	sequences := make(chan int64, concurrentEvents)
	errorsCh := make(chan error, concurrentEvents)
	events := make([]audit.Event, concurrentEvents)
	for index := range events {
		events[index] = chainEventFixture(t, principalID)
	}
	var wait sync.WaitGroup
	for index := 0; index < concurrentEvents; index++ {
		wait.Add(1)
		go func(event audit.Event) {
			defer wait.Done()
			receipt, appendErr := writer.Append(ctx, event)
			if appendErr != nil {
				errorsCh <- appendErr
				return
			}
			if !receipt.AuthorizesBackendCall() {
				errorsCh <- fmt.Errorf("committed run_started event did not authorize backend")
				return
			}
			sequences <- receipt.Sequence()
		}(events[index])
	}
	wait.Wait()
	close(errorsCh)
	close(sequences)
	for appendErr := range errorsCh {
		t.Fatalf("concurrent Append(): %v", appendErr)
	}

	persistedSequences := make([]int64, 0, concurrentEvents)
	for sequence := range sequences {
		persistedSequences = append(persistedSequences, sequence)
	}
	sort.Slice(persistedSequences, func(left, right int) bool {
		return persistedSequences[left] < persistedSequences[right]
	})
	if len(persistedSequences) != concurrentEvents {
		t.Fatalf("persisted sequence count = %d, want %d", len(persistedSequences), concurrentEvents)
	}
	for index, sequence := range persistedSequences {
		want := initialSequence + int64(index) + 1
		if sequence != want {
			t.Fatalf("sequence[%d] = %d, want %d", index, sequence, want)
		}
	}
	if err := verifier.Verify(ctx); err != nil {
		t.Fatalf("Verify(): %v", err)
	}
}

func chainEventFixture(t *testing.T, principalID string) audit.Event {
	t.Helper()
	return audit.Event{
		SchemaVersion:             1,
		EventID:                   newTestUUID(t),
		RunID:                     newTestUUID(t),
		EventType:                 audit.EventRunStarted,
		OccurredAt:                time.Now().UTC().Truncate(time.Microsecond),
		PrincipalID:               principalID,
		AuthMethod:                audit.AuthAPIKey,
		PolicyVersionHash:         integrationDigest(1),
		Decision:                  audit.DecisionAllow,
		DecisionReasonCodes:       []string{"policy_allowed"},
		RequestedModel:            "chain-model",
		ResolvedBackend:           "chain-backend",
		ContentHMACKeyID:          "chain-content-key-v1",
		RequestHMAC:               integrationDigest(2),
		RequestBytes:              128,
		PIICategories:             []string{},
		PIIMatchCounts:            map[string]int64{},
		HealthIndicatorCategories: []string{},
		SecretCategories:          []string{},
		DetectorBundleHash:        integrationDigest(3),
		Status:                    audit.StatusStarted,
		SoftwareVersion:           "chain-integration",
		ConfigHash:                integrationDigest(4),
	}
}

func integrationDigest(marker byte) audit.Digest {
	var digest audit.Digest
	digest[len(digest)-1] = marker
	return digest
}

func newTestUUID(t *testing.T) string {
	t.Helper()
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		t.Fatalf("generate UUID bytes: %v", err)
	}
	value[6] = (value[6] & 0x0f) | 0x40
	value[8] = (value[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		value[0:4], value[4:6], value[6:8], value[8:10], value[10:16])
}

func testEnvironmentValue(t *testing.T, name string) string {
	t.Helper()
	return strings.TrimSpace(os.Getenv(name))
}
