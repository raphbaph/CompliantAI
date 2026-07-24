package integration

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/raphbaph/CompliantAI/internal/store"
)

const unregisteredAuditIdentifierCanary = "PROMPT-CONTENT-CANARY-4b91e2d7"

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
		var runID string
		if err := bootstrap.QueryRow(ctx, `SELECT gen_random_uuid()`).Scan(&runID); err != nil {
			t.Fatalf("generate run ID: %v", err)
		}

		zeroHash := make([]byte, 32)
		eventHash := make([]byte, 32)
		eventHash[31] = 1
		_, err := gateway.Exec(ctx, `SELECT append_audit_event(
			$1::uuid, 'run_started', $2::uuid, 'oidc', 'allow', $3::text, 'unregistered-backend', 'started',
			$4::bytea, $5::bytea, $6::bytea, $7::bytea, $8::bytea, 'unregistered-version', $9::bytea
		)`, runID, principalID, unregisteredAuditIdentifierCanary, zeroHash, zeroHash, zeroHash, zeroHash, eventHash, zeroHash)
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
					_, err := gateway.Exec(ctx, `SELECT append_audit_event(
						$1::uuid, $2::text, $3::uuid, 'oidc', $4::text, 'local-legal', 'local-backend', $5::text,
						$6::bytea, $7::bytea, $8::bytea, $9::bytea, $10::bytea, 'integration-test', $11::bytea
					)`, runID, eventType, principalID, decision, status, zeroHash, zeroHash, zeroHash, zeroHash, eventHash, zeroHash)
					assertSQLStateMessage(t, err, "22023", "invalid audit event state")
				}
			}
		}

		for _, rolePool := range []*pgxpool.Pool{gateway, securityAdmin} {
			_, err := rolePool.Exec(ctx,
				`INSERT INTO audit_identifiers (identifier_type, identifier_value) VALUES ('model', 'direct-write')`,
			)
			assertSQLState(t, err, "42501")
		}

		var sequence int64
		err = gateway.QueryRow(ctx, `SELECT append_audit_event(
			$1::uuid, 'run_started', $2::uuid, 'oidc', 'allow', 'local-legal', 'local-backend', 'started',
			$3::bytea, $4::bytea, $5::bytea, $6::bytea, $7::bytea, 'integration-test', $8::bytea
		)`, runID, principalID, zeroHash, zeroHash, zeroHash, zeroHash, eventHash, zeroHash).Scan(&sequence)
		if err != nil {
			t.Fatalf("approved audit append: %v", err)
		}

		var count int
		if err := auditReader.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE sequence = $1`, sequence).Scan(&count); err != nil {
			t.Fatalf("audit reader select: %v", err)
		}
		if count != 1 {
			t.Fatalf("audit row count = %d, want 1", count)
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
