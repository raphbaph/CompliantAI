package integration

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/raphbaph/CompliantAI/internal/store"
)

const (
	unregisteredAuditIdentifierCanary = "PROMPT-CONTENT-CANARY-4b91e2d7"
	appendAuditEventSQL               = `SELECT append_audit_event(
		$1::smallint, $2::uuid, $3::uuid, $4::text, $5::timestamptz, $6::uuid, $7::text,
		$8::bytea, $9::bytea, $10::text, $11::text[], $12::text, $13::text, $14::text,
		$15::bytea, $16::bytea, $17::bigint, $18::bigint, $19::text[], $20::jsonb,
		$21::text[], $22::text[], $23::bytea, $24::bigint, $25::bigint, $26::bigint,
		$27::bigint, $28::text, $29::text, $30::bytea, $31::bytea, $32::text, $33::bytea
	)`
	auditRowMatchesSQL = `SELECT ROW(
		schema_version, event_id, run_id, event_type, occurred_at, principal_id, auth_method,
		oidc_issuer_hash, policy_version_hash, decision, decision_reason_codes, requested_model,
		resolved_backend, content_hmac_key_id, request_hmac, response_hmac, request_bytes,
		response_bytes, pii_categories, pii_match_counts, health_indicator_categories,
		secret_categories, detector_bundle_hash, input_tokens, output_tokens,
		reserved_cost_micros, actual_cost_micros, status, error_code, previous_event_hash,
		event_hash, software_version, config_hash
	) IS NOT DISTINCT FROM ROW(
		$2::smallint, $3::uuid, $4::uuid, $5::text, $6::timestamptz, $7::uuid, $8::text,
		$9::bytea, $10::bytea, $11::text, $12::text[], $13::text, $14::text, $15::text,
		$16::bytea, $17::bytea, $18::bigint, $19::bigint, $20::text[], $21::jsonb,
		$22::text[], $23::text[], $24::bytea, $25::bigint, $26::bigint, $27::bigint,
		$28::bigint, $29::text, $30::text, $31::bytea, $32::bytea, $33::text, $34::bytea
	) FROM audit_events WHERE sequence = $1`
)

var auditFixtureOccurredAt = time.Date(2026, time.July, 24, 10, 0, 0, 123456000, time.UTC)

func TestPostgresRoles(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	for _, envName := range []string{
		"TEST_BOOTSTRAP_DSN",
		"TEST_GATEWAY_DSN",
		"TEST_AUDIT_READER_DSN",
		"TEST_SECURITY_ADMIN_DSN",
	} {
		dsn := os.Getenv(envName)
		if dsn == "" {
			t.Skipf("%s is not set", envName)
		}
		pool, err := pgxpool.New(ctx, dsn)
		if err != nil {
			t.Fatalf("open %s: %v", envName, err)
		}
		if err := pool.Ping(ctx); err != nil {
			pool.Close()
			t.Fatalf("ping %s: %v", envName, err)
		}
		pool.Close()
	}

	bootstrap := openTestPool(t, ctx, "TEST_BOOTSTRAP_DSN")
	defer bootstrap.Close()
	var extensionVersion string
	if err := bootstrap.QueryRow(ctx, `SELECT extversion FROM pg_extension WHERE extname = 'pgaudit'`).Scan(&extensionVersion); err != nil {
		t.Fatalf("pgaudit extension is not installed: %v", err)
	}

	t.Run("role attributes are least privilege", func(t *testing.T) {
		tests := []struct {
			role     string
			canLogin bool
		}{
			{role: "gateway_runtime", canLogin: true},
			{role: "audit_reader", canLogin: true},
			{role: "security_admin", canLogin: true},
			{role: "migration_owner", canLogin: false},
		}
		for _, test := range tests {
			var canLogin, superuser, createDB, createRole, inherit, replication, bypassRLS bool
			err := bootstrap.QueryRow(ctx, `SELECT rolcanlogin, rolsuper, rolcreatedb, rolcreaterole, rolinherit, rolreplication, rolbypassrls FROM pg_roles WHERE rolname = $1`, test.role).
				Scan(&canLogin, &superuser, &createDB, &createRole, &inherit, &replication, &bypassRLS)
			if err != nil {
				t.Fatalf("read role %s: %v", test.role, err)
			}
			if canLogin != test.canLogin || superuser || createDB || createRole || inherit || replication || bypassRLS {
				t.Fatalf("role %s has unsafe attributes: login=%t super=%t createdb=%t createrole=%t inherit=%t replication=%t bypassrls=%t",
					test.role, canLogin, superuser, createDB, createRole, inherit, replication, bypassRLS)
			}
		}
	})

	t.Run("store opens runtime pool", func(t *testing.T) {
		pool, err := store.Open(ctx, os.Getenv("TEST_GATEWAY_DSN"))
		if err != nil {
			t.Fatalf("store.Open(): %v", err)
		}
		pool.Close()
	})

	t.Run("security definer execution is least privilege", func(t *testing.T) {
		functions := map[string]string{
			"admin_create_principal":          "security_admin",
			"admin_create_api_key":            "security_admin",
			"admin_disable_api_key":           "security_admin",
			"admin_set_budget":                "security_admin",
			"admin_register_audit_identifier": "security_admin",
			"append_audit_event":              "gateway_runtime",
		}
		for functionName, authorizedRole := range functions {
			for _, role := range []string{"gateway_runtime", "audit_reader", "security_admin"} {
				var allowed bool
				if err := bootstrap.QueryRow(ctx, `
					SELECT has_function_privilege($1, p.oid, 'EXECUTE')
					FROM pg_proc p
					JOIN pg_namespace n ON n.oid = p.pronamespace
					WHERE n.nspname = 'public' AND p.proname = $2
				`, role, functionName).Scan(&allowed); err != nil {
					t.Fatalf("read %s execution privilege for %s: %v", functionName, role, err)
				}
				if allowed != (role == authorizedRole) {
					t.Fatalf("role %s execute %s = %t, want %t", role, functionName, allowed, role == authorizedRole)
				}
			}
		}
	})

	t.Run("ordinary roles cannot create temporary tables", func(t *testing.T) {
		for _, envName := range []string{"TEST_GATEWAY_DSN", "TEST_AUDIT_READER_DSN", "TEST_SECURITY_ADMIN_DSN"} {
			rolePool := openTestPool(t, ctx, envName)
			_, err := rolePool.Exec(ctx, `CREATE TEMP TABLE task5_temp_denied (id BIGINT)`)
			assertSQLState(t, err, "42501")
			rolePool.Close()
		}

		migrationTx, err := bootstrap.Begin(ctx)
		if err != nil {
			t.Fatalf("begin migration-owner temporary-table probe: %v", err)
		}
		defer migrationTx.Rollback(ctx)
		if _, err := migrationTx.Exec(ctx, `SET LOCAL ROLE migration_owner`); err != nil {
			t.Fatalf("set migration owner: %v", err)
		}
		_, err = migrationTx.Exec(ctx, `CREATE TEMP TABLE task5_temp_denied (id BIGINT)`)
		assertSQLState(t, err, "42501")
	})

	t.Run("ordinary roles cannot connect to other databases", func(t *testing.T) {
		for _, envName := range []string{"TEST_GATEWAY_DSN", "TEST_AUDIT_READER_DSN", "TEST_SECURITY_ADMIN_DSN"} {
			dsn, err := url.Parse(os.Getenv(envName))
			if err != nil {
				t.Fatalf("parse %s: %v", envName, err)
			}
			dsn.Path = "/postgres"
			rolePool, err := pgxpool.New(ctx, dsn.String())
			if err != nil {
				t.Fatalf("open alternate database pool for %s: %v", envName, err)
			}
			err = rolePool.Ping(ctx)
			rolePool.Close()
			assertSQLState(t, err, "28000")
		}

		for _, role := range []string{"gateway_runtime", "audit_reader", "security_admin", "migration_owner"} {
			for _, database := range []string{"postgres", "template1"} {
				var canConnect, canCreateTemporary bool
				if err := bootstrap.QueryRow(ctx,
					`SELECT has_database_privilege($1, $2, 'CONNECT'), has_database_privilege($1, $2, 'TEMPORARY')`,
					role, database,
				).Scan(&canConnect, &canCreateTemporary); err != nil {
					t.Fatalf("read %s privileges on %s: %v", role, database, err)
				}
				if canConnect || canCreateTemporary {
					t.Fatalf("role %s retains cross-database privileges on %s: connect=%t temporary=%t", role, database, canConnect, canCreateTemporary)
				}
			}
		}
	})

	t.Run("principal administration is controlled", func(t *testing.T) {
		securityAdmin := openTestPool(t, ctx, "TEST_SECURITY_ADMIN_DSN")
		defer securityAdmin.Close()
		gateway := openTestPool(t, ctx, "TEST_GATEWAY_DSN")
		defer gateway.Close()
		auditReader := openTestPool(t, ctx, "TEST_AUDIT_READER_DSN")
		defer auditReader.Close()

		var principalID string
		err := securityAdmin.QueryRow(ctx,
			`SELECT admin_create_principal($1, $2, $3)`,
			"https://idp.customer.example", fmt.Sprintf("test-subject-%d", time.Now().UnixNano()), "integration-fixture",
		).Scan(&principalID)
		if err != nil {
			t.Fatalf("approved principal creation: %v", err)
		}

		var status string
		if err := gateway.QueryRow(ctx, `SELECT status FROM principals WHERE id = $1`, principalID).Scan(&status); err != nil {
			t.Fatalf("gateway reads principal: %v", err)
		}
		if status != "active" {
			t.Fatalf("principal status = %q, want active", status)
		}

		_, err = gateway.Exec(ctx, `INSERT INTO principals (id, status) VALUES (gen_random_uuid(), 'active')`)
		assertSQLState(t, err, "42501")

		_, err = auditReader.Exec(ctx, `SELECT id FROM principals LIMIT 1`)
		assertSQLState(t, err, "42501")
	})

	t.Run("API keys are managed only through admin functions", func(t *testing.T) {
		securityAdmin := openTestPool(t, ctx, "TEST_SECURITY_ADMIN_DSN")
		defer securityAdmin.Close()
		gateway := openTestPool(t, ctx, "TEST_GATEWAY_DSN")
		defer gateway.Close()
		auditReader := openTestPool(t, ctx, "TEST_AUDIT_READER_DSN")
		defer auditReader.Close()

		var principalID string
		if err := securityAdmin.QueryRow(ctx,
			`SELECT admin_create_principal($1, $2, $3)`,
			"https://idp.customer.example", fmt.Sprintf("api-key-subject-%d", time.Now().UnixNano()), "api-key-fixture",
		).Scan(&principalID); err != nil {
			t.Fatalf("create API-key principal: %v", err)
		}
		keyID := fmt.Sprintf("key-%d", time.Now().UnixNano())
		verifier := "hmac-sha256:" + strings.Repeat("a", 64)
		if _, err := securityAdmin.Exec(ctx,
			`SELECT admin_create_api_key($1, $2, $3::uuid, statement_timestamp() + interval '1 day')`,
			keyID, verifier, principalID,
		); err != nil {
			t.Fatalf("create API key through admin function: %v", err)
		}

		var storedVerifier string
		var disabled bool
		if err := gateway.QueryRow(ctx,
			`SELECT secret_verifier, disabled_at IS NOT NULL FROM api_keys WHERE key_id = $1`, keyID,
		).Scan(&storedVerifier, &disabled); err != nil {
			t.Fatalf("gateway reads API key verifier: %v", err)
		}
		if storedVerifier != verifier || disabled {
			t.Fatalf("unexpected API key state after creation")
		}
		_, err := securityAdmin.Exec(ctx, `UPDATE api_keys SET disabled_at = statement_timestamp() WHERE key_id = $1`, keyID)
		assertSQLState(t, err, "42501")
		if _, err := securityAdmin.Exec(ctx, `SELECT admin_disable_api_key($1)`, keyID); err != nil {
			t.Fatalf("disable API key through admin function: %v", err)
		}
		if err := gateway.QueryRow(ctx,
			`SELECT disabled_at IS NOT NULL FROM api_keys WHERE key_id = $1`, keyID,
		).Scan(&disabled); err != nil {
			t.Fatalf("gateway reads disabled API key: %v", err)
		}
		if !disabled {
			t.Fatal("API key remains enabled after controlled disable")
		}
		_, err = auditReader.Exec(ctx, `SELECT key_id FROM api_keys LIMIT 1`)
		assertSQLState(t, err, "42501")
	})

	t.Run("budget administration is controlled", func(t *testing.T) {
		securityAdmin := openTestPool(t, ctx, "TEST_SECURITY_ADMIN_DSN")
		defer securityAdmin.Close()
		gateway := openTestPool(t, ctx, "TEST_GATEWAY_DSN")
		defer gateway.Close()
		auditReader := openTestPool(t, ctx, "TEST_AUDIT_READER_DSN")
		defer auditReader.Close()

		var principalID string
		err := securityAdmin.QueryRow(ctx,
			`SELECT admin_create_principal($1, $2, $3)`,
			"https://idp.customer.example", fmt.Sprintf("budget-subject-%d", time.Now().UnixNano()), "budget-fixture",
		).Scan(&principalID)
		if err != nil {
			t.Fatalf("create budget principal: %v", err)
		}
		if _, err := securityAdmin.Exec(ctx, `SELECT admin_set_budget($1, $2, $3)`, principalID, int64(100_000), int64(1_000_000)); err != nil {
			t.Fatalf("approved budget setup: %v", err)
		}

		var dailyLimit, monthlyLimit int64
		if err := gateway.QueryRow(ctx,
			`SELECT daily_limit_micros, monthly_limit_micros FROM budget_accounts WHERE principal_id = $1`, principalID,
		).Scan(&dailyLimit, &monthlyLimit); err != nil {
			t.Fatalf("gateway reads budget: %v", err)
		}
		if dailyLimit != 100_000 || monthlyLimit != 1_000_000 {
			t.Fatalf("budget limits = %d/%d", dailyLimit, monthlyLimit)
		}

		_, err = gateway.Exec(ctx, `UPDATE budget_accounts SET daily_limit_micros = 1 WHERE principal_id = $1`, principalID)
		assertSQLState(t, err, "42501")
		_, err = auditReader.Exec(ctx, `SELECT principal_id FROM budget_accounts LIMIT 1`)
		assertSQLState(t, err, "42501")
	})

	t.Run("audit writes are append only", func(t *testing.T) {
		securityAdmin := openTestPool(t, ctx, "TEST_SECURITY_ADMIN_DSN")
		defer securityAdmin.Close()
		gateway := openTestPool(t, ctx, "TEST_GATEWAY_DSN")
		defer gateway.Close()
		auditReader := openTestPool(t, ctx, "TEST_AUDIT_READER_DSN")
		defer auditReader.Close()

		var principalID string
		if err := securityAdmin.QueryRow(ctx,
			`SELECT admin_create_principal($1, $2, $3)`,
			"https://idp.customer.example", fmt.Sprintf("audit-subject-%d", time.Now().UnixNano()), "audit-fixture",
		).Scan(&principalID); err != nil {
			t.Fatalf("create audit principal: %v", err)
		}
		var eventID, runID string
		if err := bootstrap.QueryRow(ctx, `SELECT gen_random_uuid(), gen_random_uuid()`).Scan(&eventID, &runID); err != nil {
			t.Fatalf("generate event and run IDs: %v", err)
		}

		evidenceHash := make([]byte, 32)
		evidenceHash[0] = 1
		eventHash := make([]byte, 32)
		eventHash[31] = 1
		validMetadata := validAuditMetadataFixture(evidenceHash)
		_, err := appendAuditFixture(
			ctx, gateway, eventID, runID, principalID, "run_started", "allow", "started",
			unregisteredAuditIdentifierCanary, "unregistered-backend", "unregistered-version",
			"unregistered-content-key", evidenceHash, eventHash, validMetadata,
		)
		assertSQLStateMessage(t, err, "22023", "unregistered audit identifier")
		var rejectedCount int
		if err := auditReader.QueryRow(ctx,
			`SELECT count(*) FROM audit_events WHERE requested_model = $1`, unregisteredAuditIdentifierCanary,
		).Scan(&rejectedCount); err != nil {
			t.Fatalf("read rejected audit rows: %v", err)
		}
		if rejectedCount != 0 {
			t.Fatalf("rejected identifier persisted in %d audit rows", rejectedCount)
		}

		for identifierType, identifierValue := range map[string]string{
			"model":            "local-legal",
			"backend":          "local-backend",
			"software_version": "integration-test",
			"content_hmac_key": "content-key-v1",
		} {
			if _, err := securityAdmin.Exec(ctx,
				`SELECT admin_register_audit_identifier($1, $2)`, identifierType, identifierValue,
			); err != nil {
				t.Fatalf("register %s identifier: %v", identifierType, err)
			}
		}
		for _, envName := range []string{"TEST_GATEWAY_DSN", "TEST_AUDIT_READER_DSN"} {
			rolePool := openTestPool(t, ctx, envName)
			_, err := rolePool.Exec(ctx, `SELECT admin_register_audit_identifier('model', 'unauthorized')`)
			assertSQLState(t, err, "42501")
			rolePool.Close()
		}

		validStates := map[string]struct {
			decision string
			status   string
		}{
			"run_started":   {decision: "allow", status: "started"},
			"run_completed": {decision: "allow", status: "completed"},
			"run_failed":    {decision: "allow", status: "failed"},
			"run_denied":    {decision: "deny", status: "denied"},
		}
		for eventType, valid := range validStates {
			for _, decision := range []string{"allow", "deny"} {
				for _, status := range []string{"started", "completed", "failed", "denied"} {
					if decision == valid.decision && status == valid.status {
						continue
					}
					_, err := appendAuditFixture(
						ctx, gateway, eventID, runID, principalID, eventType, decision, status,
						"local-legal", "local-backend", "integration-test", "content-key-v1", evidenceHash, eventHash,
						validMetadata,
					)
					assertSQLStateMessage(t, err, "22023", "invalid audit event state")
				}
			}
		}

		metadataRejections := []struct {
			name   string
			mutate func(*auditMetadataFixture)
		}{
			{name: "decision reason content", mutate: func(metadata *auditMetadataFixture) {
				metadata.decisionReasonCodes = []string{unregisteredAuditIdentifierCanary}
			}},
			{name: "duplicate decision reason", mutate: func(metadata *auditMetadataFixture) {
				metadata.decisionReasonCodes = []string{"policy_allowed", "policy_allowed"}
			}},
			{name: "oversized decision reasons", mutate: func(metadata *auditMetadataFixture) {
				metadata.decisionReasonCodes = make([]string, 65)
				for index := range metadata.decisionReasonCodes {
					metadata.decisionReasonCodes[index] = fmt.Sprintf("reason_%d", index)
				}
			}},
			{name: "PII category content", mutate: func(metadata *auditMetadataFixture) {
				metadata.piiCategories = []string{unregisteredAuditIdentifierCanary}
			}},
			{name: "PII count key content", mutate: func(metadata *auditMetadataFixture) {
				metadata.piiMatchCounts = map[string]any{unregisteredAuditIdentifierCanary: 1}
			}},
			{name: "negative PII count", mutate: func(metadata *auditMetadataFixture) { metadata.piiMatchCounts = map[string]any{"tax_id": -1} }},
			{name: "noninteger PII count", mutate: func(metadata *auditMetadataFixture) { metadata.piiMatchCounts = map[string]any{"tax_id": "one"} }},
			{name: "oversized PII count", mutate: func(metadata *auditMetadataFixture) {
				metadata.piiMatchCounts = map[string]any{"tax_id": json.Number("9223372036854775808")}
			}},
			{name: "health category content", mutate: func(metadata *auditMetadataFixture) {
				metadata.healthIndicatorCategories = []string{unregisteredAuditIdentifierCanary}
			}},
			{name: "secret category content", mutate: func(metadata *auditMetadataFixture) {
				metadata.secretCategories = []string{unregisteredAuditIdentifierCanary}
			}},
			{name: "error code content", mutate: func(metadata *auditMetadataFixture) {
				value := unregisteredAuditIdentifierCanary
				metadata.errorCode = &value
			}},
		}
		for _, rejection := range metadataRejections {
			t.Run(rejection.name, func(t *testing.T) {
				var rejectedEventID string
				if err := bootstrap.QueryRow(ctx, `SELECT gen_random_uuid()`).Scan(&rejectedEventID); err != nil {
					t.Fatalf("generate rejected event ID: %v", err)
				}
				metadata := validMetadata
				rejection.mutate(&metadata)
				_, err := appendAuditFixture(
					ctx, gateway, rejectedEventID, runID, principalID, "run_completed", "allow", "completed",
					"local-legal", "local-backend", "integration-test", "content-key-v1",
					evidenceHash, eventHash, metadata,
				)
				assertSQLStateMessage(t, err, "22023", "invalid audit event metadata")
				if strings.Contains(err.Error(), unregisteredAuditIdentifierCanary) {
					t.Fatal("database error echoed rejected metadata")
				}
			})
		}

		arrayShapeRejections := []struct {
			name  string
			value pgtype.Array[string]
		}{
			{
				name: "multidimensional decision reasons",
				value: pgtype.Array[string]{
					Elements: []string{"alpha", "beta", "gamma", "delta"},
					Dims: []pgtype.ArrayDimension{
						{Length: 2, LowerBound: 1},
						{Length: 2, LowerBound: 1},
					},
					Valid: true,
				},
			},
			{
				name: "zero-based decision reasons",
				value: pgtype.Array[string]{
					Elements: []string{"alpha", "beta"},
					Dims:     []pgtype.ArrayDimension{{Length: 2, LowerBound: 0}},
					Valid:    true,
				},
			},
		}
		for _, rejection := range arrayShapeRejections {
			t.Run(rejection.name, func(t *testing.T) {
				var rejectedEventID string
				if err := bootstrap.QueryRow(ctx, `SELECT gen_random_uuid()`).Scan(&rejectedEventID); err != nil {
					t.Fatalf("generate rejected event ID: %v", err)
				}
				arguments := auditAppendArguments(
					rejectedEventID, runID, principalID, "run_completed", "allow", "completed",
					"local-legal", "local-backend", "integration-test", "content-key-v1",
					evidenceHash, eventHash, validMetadata,
				)
				arguments[10] = rejection.value
				var rejectedSequence int64
				err := gateway.QueryRow(ctx, appendAuditEventSQL, arguments...).Scan(&rejectedSequence)
				assertSQLStateMessage(t, err, "22023", "invalid audit event metadata")
			})
		}

		for _, rolePool := range []*pgxpool.Pool{gateway, securityAdmin} {
			_, err := rolePool.Exec(ctx,
				`INSERT INTO audit_identifiers (identifier_type, identifier_value) VALUES ('model', 'direct-write')`,
			)
			assertSQLState(t, err, "42501")
		}

		sequence, err := appendAuditFixture(
			ctx, gateway, eventID, runID, principalID, "run_completed", "allow", "completed",
			"local-legal", "local-backend", "integration-test", "content-key-v1", evidenceHash, eventHash,
			validMetadata,
		)
		if err != nil {
			t.Fatalf("approved audit append: %v", err)
		}

		arguments := auditAppendArguments(
			eventID, runID, principalID, "run_completed", "allow", "completed",
			"local-legal", "local-backend", "integration-test", "content-key-v1",
			evidenceHash, eventHash, validMetadata,
		)
		matchArguments := append([]any{sequence}, arguments...)
		var rowMatches bool
		if err := auditReader.QueryRow(ctx, auditRowMatchesSQL, matchArguments...).Scan(&rowMatches); err != nil {
			t.Fatalf("compare persisted canonical event: %v", err)
		}
		if !rowMatches {
			t.Fatal("persisted canonical event differs from supplied values")
		}

		_, err = gateway.Exec(ctx, `INSERT INTO audit_events (event_id) VALUES (gen_random_uuid())`)
		assertSQLState(t, err, "42501")

		for _, envName := range []string{"TEST_GATEWAY_DSN", "TEST_AUDIT_READER_DSN", "TEST_SECURITY_ADMIN_DSN"} {
			rolePool := openTestPool(t, ctx, envName)
			_, err = rolePool.Exec(ctx, `UPDATE audit_events SET status = 'failed' WHERE sequence = $1`, sequence)
			assertSQLState(t, err, "42501")
			_, err = rolePool.Exec(ctx, `DELETE FROM audit_events WHERE sequence = $1`, sequence)
			assertSQLState(t, err, "42501")
			rolePool.Close()
		}

		_, err = securityAdmin.Exec(ctx, `ALTER TABLE audit_events DISABLE TRIGGER USER`)
		assertSQLState(t, err, "42501")

		migrationTx, err := bootstrap.Begin(ctx)
		if err != nil {
			t.Fatalf("begin migration-owner trigger probe: %v", err)
		}
		defer migrationTx.Rollback(ctx)
		if _, err := migrationTx.Exec(ctx, `SET LOCAL ROLE migration_owner`); err != nil {
			t.Fatalf("set migration owner: %v", err)
		}
		_, err = migrationTx.Exec(ctx, `UPDATE audit_events SET status = status WHERE sequence = $1`, sequence)
		assertSQLState(t, err, "42501")
	})

	t.Run("pgaudit records privileged attempts without parameters", func(t *testing.T) {
		containerName := os.Getenv("TEST_POSTGRES_CONTAINER")
		if containerName == "" {
			t.Skip("TEST_POSTGRES_CONTAINER is not set")
		}
		gateway := openTestPool(t, ctx, "TEST_GATEWAY_DSN")
		defer gateway.Close()
		securityAdmin := openTestPool(t, ctx, "TEST_SECURITY_ADMIN_DSN")
		defer securityAdmin.Close()

		adminAuditMarker := fmt.Sprintf("task5-admin-audit-%d", time.Now().UnixNano())
		adminAuditDSN, err := url.Parse(os.Getenv("TEST_SECURITY_ADMIN_DSN"))
		if err != nil {
			t.Fatalf("parse security-admin DSN: %v", err)
		}
		adminAuditQuery := adminAuditDSN.Query()
		adminAuditQuery.Set("application_name", adminAuditMarker)
		adminAuditDSN.RawQuery = adminAuditQuery.Encode()
		auditedAdmin, err := pgxpool.New(ctx, adminAuditDSN.String())
		if err != nil {
			t.Fatalf("open tagged security-admin pool: %v", err)
		}
		defer auditedAdmin.Close()

		var auditedPrincipalID string
		if err := auditedAdmin.QueryRow(ctx,
			`SELECT admin_create_principal($1, $2, $3)`,
			"https://idp.customer.example", fmt.Sprintf("admin-audit-subject-%d", time.Now().UnixNano()), "admin-audit-fixture",
		).Scan(&auditedPrincipalID); err != nil {
			t.Fatalf("audited principal administration: %v", err)
		}
		auditedKeyID := fmt.Sprintf("audit-key-%d", time.Now().UnixNano())
		const auditedVerifierCanary = "hmac-sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
		if _, err := auditedAdmin.Exec(ctx,
			`SELECT admin_create_api_key($1, $2, $3::uuid, statement_timestamp() + interval '1 day')`,
			auditedKeyID, auditedVerifierCanary, auditedPrincipalID,
		); err != nil {
			t.Fatalf("audited API-key administration: %v", err)
		}
		if _, err := auditedAdmin.Exec(ctx,
			`SELECT admin_set_budget($1::uuid, $2, $3)`, auditedPrincipalID, int64(100_000), int64(1_000_000),
		); err != nil {
			t.Fatalf("audited budget administration: %v", err)
		}
		if _, err := auditedAdmin.Exec(ctx,
			`SELECT admin_register_audit_identifier('software_version', $1)`, fmt.Sprintf("admin-audit-%d", time.Now().UnixNano()),
		); err != nil {
			t.Fatalf("audited identifier administration: %v", err)
		}

		const contentCanary = "DB-LOG-CONTENT-CANARY-7f2e91d4"
		_, err = gateway.Exec(ctx,
			`INSERT INTO principals (id, display_label, status) VALUES (gen_random_uuid(), $1, 'active')`,
			contentCanary,
		)
		assertSQLState(t, err, "42501")
		_, err = securityAdmin.Exec(ctx, `CREATE TABLE task5_forbidden_ddl_probe (id BIGINT)`)
		assertSQLState(t, err, "42501")

		output, err := exec.CommandContext(ctx, "docker", "logs", containerName).CombinedOutput()
		if err != nil {
			t.Fatalf("read PostgreSQL container logs: %v", err)
		}
		logs := string(output)
		var taggedAdminAudit strings.Builder
		for _, line := range strings.Split(logs, "\n") {
			if strings.Contains(line, adminAuditMarker) && strings.Contains(line, "AUDIT:") {
				taggedAdminAudit.WriteString(line)
				taggedAdminAudit.WriteByte('\n')
			}
		}
		for _, functionName := range []string{
			"admin_create_principal",
			"admin_create_api_key",
			"admin_set_budget",
			"admin_register_audit_identifier",
		} {
			if !strings.Contains(taggedAdminAudit.String(), functionName) {
				t.Fatalf("tagged pgaudit records do not contain successful call to %s", functionName)
			}
		}
		for _, expected := range []string{"INSERT INTO principals", "CREATE TABLE task5_forbidden_ddl_probe", "permission denied"} {
			if !strings.Contains(logs, expected) {
				t.Fatalf("PostgreSQL logs do not contain %q", expected)
			}
		}
		for _, canary := range []string{contentCanary, unregisteredAuditIdentifierCanary, auditedVerifierCanary} {
			if strings.Contains(logs, canary) {
				t.Fatal("PostgreSQL logs contain bound content canary")
			}
		}
		credentialCanaries := make([]string, 0, 4)
		for _, envName := range []string{
			"TEST_BOOTSTRAP_DSN",
			"TEST_GATEWAY_DSN",
			"TEST_AUDIT_READER_DSN",
			"TEST_SECURITY_ADMIN_DSN",
		} {
			dsn, err := url.Parse(os.Getenv(envName))
			if err != nil {
				t.Fatalf("parse %s: %v", envName, err)
			}
			password, present := dsn.User.Password()
			if !present || password == "" {
				t.Fatalf("%s has no test password", envName)
			}
			credentialCanaries = append(credentialCanaries, password)
			if strings.Contains(logs, password) {
				t.Fatalf("PostgreSQL logs contain credential from %s", envName)
			}
		}

		configuredEnvironment, err := exec.CommandContext(ctx,
			"docker", "inspect", "--format", "{{json .Config.Env}}", containerName,
		).CombinedOutput()
		if err != nil {
			t.Fatalf("inspect PostgreSQL container environment: %v", err)
		}
		runtimeEnvironment, err := exec.CommandContext(ctx,
			"docker", "exec", containerName, "env",
		).CombinedOutput()
		if err != nil {
			t.Fatalf("inspect PostgreSQL runtime environment: %v", err)
		}
		for _, password := range credentialCanaries {
			if strings.Contains(string(configuredEnvironment), password) || strings.Contains(string(runtimeEnvironment), password) {
				t.Fatal("PostgreSQL container or process environment contains a database credential")
			}
		}
	})
}

type auditMetadataFixture struct {
	decisionReasonCodes       []string
	responseHMAC              []byte
	requestBytes              int64
	responseBytes             *int64
	piiCategories             []string
	piiMatchCounts            map[string]any
	healthIndicatorCategories []string
	secretCategories          []string
	inputTokens               *int64
	outputTokens              *int64
	reservedCostMicros        *int64
	actualCostMicros          *int64
	errorCode                 *string
}

func validAuditMetadataFixture(evidenceHash []byte) auditMetadataFixture {
	responseBytes := int64(256)
	inputTokens := int64(12)
	outputTokens := int64(8)
	reservedCostMicros := int64(300)
	actualCostMicros := int64(220)
	return auditMetadataFixture{
		decisionReasonCodes:       []string{"policy_allowed", "region_allowed"},
		responseHMAC:              evidenceHash,
		requestBytes:              128,
		responseBytes:             &responseBytes,
		piiCategories:             []string{"email_address", "tax_id"},
		piiMatchCounts:            map[string]any{"email_address": int64(2), "tax_id": int64(1)},
		healthIndicatorCategories: []string{"diagnosis_indicator", "medication_indicator"},
		secretCategories:          []string{"api_credential", "private_key"},
		inputTokens:               &inputTokens,
		outputTokens:              &outputTokens,
		reservedCostMicros:        &reservedCostMicros,
		actualCostMicros:          &actualCostMicros,
	}
}

func auditAppendArguments(
	eventID string,
	runID string,
	principalID string,
	eventType string,
	decision string,
	status string,
	model string,
	backend string,
	softwareVersion string,
	contentHMACKeyID string,
	evidenceHash []byte,
	eventHash []byte,
	metadata auditMetadataFixture,
) []any {
	return []any{
		int16(1), eventID, runID, eventType, auditFixtureOccurredAt, principalID, "oidc",
		evidenceHash, evidenceHash, decision, metadata.decisionReasonCodes, model, backend, contentHMACKeyID,
		evidenceHash, metadata.responseHMAC, metadata.requestBytes, metadata.responseBytes,
		metadata.piiCategories, metadata.piiMatchCounts, metadata.healthIndicatorCategories,
		metadata.secretCategories, evidenceHash, metadata.inputTokens, metadata.outputTokens,
		metadata.reservedCostMicros, metadata.actualCostMicros, status, metadata.errorCode,
		evidenceHash, eventHash, softwareVersion, evidenceHash,
	}
}

func appendAuditFixture(
	ctx context.Context,
	pool *pgxpool.Pool,
	eventID string,
	runID string,
	principalID string,
	eventType string,
	decision string,
	status string,
	model string,
	backend string,
	softwareVersion string,
	contentHMACKeyID string,
	evidenceHash []byte,
	eventHash []byte,
	metadata auditMetadataFixture,
) (int64, error) {
	arguments := auditAppendArguments(
		eventID, runID, principalID, eventType, decision, status, model, backend,
		softwareVersion, contentHMACKeyID, evidenceHash, eventHash, metadata,
	)
	var sequence int64
	err := pool.QueryRow(ctx, appendAuditEventSQL, arguments...).Scan(&sequence)
	return sequence, err
}

func assertSQLState(t *testing.T, err error, want string) {
	t.Helper()
	if err == nil {
		t.Fatalf("database operation succeeded, want SQLSTATE %s", want)
	}
	var postgresError *pgconn.PgError
	if !errors.As(err, &postgresError) {
		t.Fatalf("database error = %T %v, want pg error %s", err, err, want)
	}
	if postgresError.Code != want {
		t.Fatalf("SQLSTATE = %s, want %s: %v", postgresError.Code, want, err)
	}
}

func assertSQLStateMessage(t *testing.T, err error, wantCode, wantMessage string) {
	t.Helper()
	assertSQLState(t, err, wantCode)
	var postgresError *pgconn.PgError
	if !errors.As(err, &postgresError) {
		t.Fatalf("database error = %T %v, want pg error", err, err)
	}
	if postgresError.Message != wantMessage {
		t.Fatalf("database message = %q, want %q", postgresError.Message, wantMessage)
	}
}

func openTestPool(t *testing.T, ctx context.Context, envName string) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv(envName)
	if dsn == "" {
		t.Skipf("%s is not set", envName)
	}
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("open %s: %v", envName, err)
	}
	return pool
}
