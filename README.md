# pg_command_fw

A PostgreSQL extension that intercepts and optionally blocks DDL and utility commands via a `ProcessUtility` hook. Each command category is independently controlled by a GUC flag.

## Installation

Add to `postgresql.conf`:

```
shared_preload_libraries = 'pg_command_fw'
```

Then create the extension in the target database:

```sql
CREATE EXTENSION pg_command_fw;
```

## Command categories

| Category | GUC | Default | Who is blocked |
|---|---|---|---|
| `TRUNCATE` | `pg_command_fw.block_truncate` | `on` | Non-superusers |
| `DROP TABLE` | `pg_command_fw.block_drop_table` | `off` | Non-superusers (opt-in) |
| `ALTER SYSTEM` | `pg_command_fw.block_alter_system` | `on` | Everyone including superusers |
| `LOAD` | `pg_command_fw.block_load` | `on` | Everyone including superusers |
| `COPY … PROGRAM` | `pg_command_fw.block_copy_program` | `on` | Everyone including superusers |
| Plain `COPY` | `pg_command_fw.block_copy` | `off` | Non-superusers (opt-in) |

Superusers are always exempt from non-superuser checks unless they appear in `pg_command_fw.blocked_roles`.

## GUC reference

### Master switch

**`pg_command_fw.enabled`** (bool, default `on`)
Set to `off` to disable all firewall checks without unloading the extension.

### Per-category flags

**`pg_command_fw.block_truncate`** (bool, default `on`)
Block `TRUNCATE` for non-superusers.

**`pg_command_fw.block_drop_table`** (bool, default `off`)
Block `DROP TABLE` for non-superusers. When `production_schemas` is set, only drops targeting those schemas are blocked; otherwise all `DROP TABLE` is blocked.

**`pg_command_fw.production_schemas`** (string, default empty)
Comma-separated list of schemas for `DROP TABLE` checks. Only schema-qualified table names are matched; unqualified names are not resolved via `search_path`.

**`pg_command_fw.block_alter_system`** (bool, default `on`)
Block `ALTER SYSTEM` for all roles including superusers.

**`pg_command_fw.block_load`** (bool, default `on`)
Block `LOAD` (dynamic library loading) for all roles including superusers.

**`pg_command_fw.block_copy_program`** (bool, default `on`)
Block `COPY … TO/FROM PROGRAM` for all roles including superusers. Prevents shell command execution via COPY.

**`pg_command_fw.block_copy`** (bool, default `off`)
Block plain `COPY` (to/from file or stdout) for non-superusers. Superusers are exempt unless listed in `blocked_roles`.

### Cross-category

**`pg_command_fw.blocked_roles`** (string, default empty)
Comma-separated list of roles that are always blocked from any firewall-governed command, regardless of superuser status or per-category flags.

**`pg_command_fw.hint`** (string, default empty)
Custom hint message appended to the error when a command is blocked (e.g. `'Contact your DBA to request access'`).

**`pg_command_fw.audit_log_enabled`** (bool, default `on`)
Write every intercepted command to `command_fw.audit_log` via SPI. Blocked events are best-effort: the INSERT is rolled back when the transaction aborts, so the server log is authoritative for blocked events.

## Audit log

Every intercepted command (allowed or blocked) is recorded in `command_fw.audit_log`:

| Column | Type | Description |
|---|---|---|
| `id` | bigint | Auto-increment primary key |
| `ts` | timestamptz | Event timestamp |
| `session_user_name` | text | Session-level user |
| `current_user_name` | text | Current (possibly SET ROLE) user |
| `query_text` | text | Original query string |
| `command_type` | text | e.g. `TRUNCATE`, `DROP_TABLE`, `ALTER_SYSTEM`, `LOAD`, `COPY_PROGRAM`, `COPY` |
| `target_schema` | text | Schema that triggered the block (DROP TABLE with `production_schemas`) |
| `target_object` | text | Object name (LOAD: library path) |
| `client_addr` | inet | Client IP address |
| `application_name` | text | `application_name` setting |
| `blocked` | bool | Whether the command was blocked |
| `block_reason` | text | Internal reason code |

## Examples

Block `TRUNCATE` and `DROP TABLE` in production schemas for all non-superusers:

```sql
ALTER SYSTEM SET pg_command_fw.block_truncate = on;
ALTER SYSTEM SET pg_command_fw.block_drop_table = on;
ALTER SYSTEM SET pg_command_fw.production_schemas = 'public, payments';
ALTER SYSTEM SET pg_command_fw.hint = 'File a ticket at https://internal/infra';
SELECT pg_reload_conf();
```

Prevent a specific role from running any governed command even if it is a superuser:

```sql
ALTER SYSTEM SET pg_command_fw.blocked_roles = 'app_deploy';
SELECT pg_reload_conf();
```

Temporarily disable the firewall for a maintenance session:

```sql
SET pg_command_fw.enabled = off;
TRUNCATE big_table;
SET pg_command_fw.enabled = on;
```
