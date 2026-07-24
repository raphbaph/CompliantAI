ALTER ROLE gateway_runtime SET statement_timeout = '30s';
ALTER ROLE gateway_runtime SET lock_timeout = '5s';
ALTER ROLE gateway_runtime SET idle_in_transaction_session_timeout = '30s';
ALTER ROLE audit_reader SET statement_timeout = '60s';
ALTER ROLE audit_reader SET idle_in_transaction_session_timeout = '30s';
ALTER ROLE security_admin SET statement_timeout = '30s';
ALTER ROLE security_admin SET lock_timeout = '5s';
ALTER ROLE security_admin SET idle_in_transaction_session_timeout = '30s';
ALTER ROLE security_admin SET pgaudit.log = 'function,write,ddl,role';

COMMENT ON EXTENSION pgaudit IS 'Database audit logging for administrative and write activity';
