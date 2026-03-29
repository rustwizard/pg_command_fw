-- pg_command_fw: ProcessUtility hook firewall for DDL/utility commands.
-- To activate for all connections, add to postgresql.conf:
--   shared_preload_libraries = 'pg_command_fw'

CREATE SCHEMA IF NOT EXISTS command_fw;

-- Audit log for all intercepted DDL/utility commands.
--
-- NOTE: for *blocked* commands the INSERT is performed before ERROR is raised,
-- so it will be rolled back when the current transaction aborts.  The server log
-- (LOG: blocked ...) is the authoritative record for blocked events.
-- Allowed commands commit normally and their rows persist here.
CREATE TABLE command_fw.audit_log (
    id                bigserial   NOT NULL,
    -- clock_timestamp() captures the actual wall-clock time; now() would give
    -- the transaction start time, which is the same row for every statement in
    -- a multi-statement transaction.
    ts                timestamptz NOT NULL DEFAULT clock_timestamp(),
    -- Both user fields are recorded because SET ROLE makes them diverge:
    -- session_user_name is who actually authenticated, current_user_name is the
    -- effective role at the time of the command.
    session_user_name text        NOT NULL,
    current_user_name text        NOT NULL,
    query_text        text        NOT NULL,
    -- Command category: 'TRUNCATE' | 'DROP_TABLE' | 'ALTER_SYSTEM' | 'LOAD' | 'COPY_PROGRAM'
    command_type      text        NOT NULL,
    -- For DROP_TABLE: the production schema that triggered the block (NULL otherwise).
    target_schema     text,
    -- For LOAD: the library filename.  NULL for other command types.
    target_object     text,
    -- inet_client_addr() returns NULL for local (Unix-socket) connections.
    client_addr       inet,
    application_name  text,
    blocked           bool        NOT NULL,
    -- NULL when not blocked; one of: 'role_listed', 'truncate_non_superuser',
    -- 'drop_production_table', 'alter_system', 'load', 'copy_program' when blocked.
    block_reason      text,
    PRIMARY KEY (id)
);

-- Index for time-range queries and dashboards.
CREATE INDEX ON command_fw.audit_log (ts);
-- Index for per-user audits.
CREATE INDEX ON command_fw.audit_log (current_user_name);
-- Index for per-command-type queries.
CREATE INDEX ON command_fw.audit_log (command_type);
-- Partial index: fast scan of blocked-only events (typically a small fraction).
CREATE INDEX ON command_fw.audit_log (ts) WHERE blocked;

-- Lock down the schema and table; superusers can explicitly grant SELECT to
-- monitoring roles as needed.
REVOKE ALL ON SCHEMA command_fw FROM PUBLIC;
REVOKE ALL ON command_fw.audit_log FROM PUBLIC;
