#!/usr/bin/env bash
set -euo pipefail

PASS=0
FAIL=0

pass() { echo "PASS: $1"; PASS=$((PASS + 1)); }
fail() { echo "FAIL: $1"; FAIL=$((FAIL + 1)); }

# psql as the superuser (postgres)
SU="psql"
# psql as a non-superuser
RU="psql -U testuser"

echo "=== Setting up ==="
psql -c "CREATE EXTENSION IF NOT EXISTS pg_command_fw;"
psql -c "DROP OWNED BY testuser;" 2>/dev/null || true
psql -c "DROP ROLE IF EXISTS testuser;"
psql -c "CREATE ROLE testuser LOGIN PASSWORD 'testpass';"
psql -c "GRANT CONNECT ON DATABASE testdb TO testuser;"
export PGPASSWORD=postgres

# Helper: run a query and return a single trimmed value.
q() { psql -t -A -c "$1"; }

echo ""
echo "=== TRUNCATE ==="

echo ""
echo "--- Test 1: non-superuser TRUNCATE is blocked ---"
psql -c "CREATE TABLE IF NOT EXISTS trunc_test (id int);"
psql -c "GRANT TRUNCATE ON trunc_test TO testuser;"
out=$(PGPASSWORD=testpass $RU -c "TRUNCATE trunc_test;" 2>&1 || true)
if echo "$out" | grep -q "TRUNCATE command is not allowed"; then
    pass "non-superuser TRUNCATE blocked"
else
    fail "non-superuser TRUNCATE not blocked; got: $out"
fi

echo ""
echo "--- Test 2: superuser TRUNCATE is allowed ---"
out=$($SU -c "TRUNCATE trunc_test;" 2>&1)
if ! echo "$out" | grep -q "not allowed"; then
    pass "superuser TRUNCATE allowed"
else
    fail "superuser TRUNCATE blocked; got: $out"
fi
psql -c "DROP TABLE trunc_test;"

echo ""
echo "--- Test 3: block_truncate=off -> non-superuser TRUNCATE is allowed ---"
psql -c "CREATE TABLE IF NOT EXISTS trunc_test2 (id int);"
psql -c "GRANT TRUNCATE ON trunc_test2 TO testuser;"
psql -c "ALTER ROLE testuser SET pg_command_fw.block_truncate = off;"
out=$(PGPASSWORD=testpass $RU -c "TRUNCATE trunc_test2;" 2>&1)
if ! echo "$out" | grep -q "not allowed"; then
    pass "non-superuser TRUNCATE allowed when block_truncate=off"
else
    fail "non-superuser TRUNCATE blocked when block_truncate=off; got: $out"
fi
psql -c "ALTER ROLE testuser RESET pg_command_fw.block_truncate;"
psql -c "DROP TABLE trunc_test2;"

echo ""
echo "=== ALTER SYSTEM ==="

echo ""
echo "--- Test 4: superuser ALTER SYSTEM is blocked ---"
out=$($SU -c "ALTER SYSTEM SET work_mem = '8MB';" 2>&1 || true)
if echo "$out" | grep -q "ALTER SYSTEM command is not allowed"; then
    pass "superuser ALTER SYSTEM blocked"
else
    fail "superuser ALTER SYSTEM not blocked; got: $out"
fi

echo ""
echo "--- Test 5: non-superuser ALTER SYSTEM is blocked ---"
out=$(PGPASSWORD=testpass $RU -c "ALTER SYSTEM SET work_mem = '8MB';" 2>&1 || true)
if echo "$out" | grep -q "ALTER SYSTEM command is not allowed\|must be superuser"; then
    pass "non-superuser ALTER SYSTEM blocked"
else
    fail "non-superuser ALTER SYSTEM not blocked; got: $out"
fi

echo ""
echo "--- Test 6: block_alter_system=off -> superuser ALTER SYSTEM is allowed ---"
# SET is session-scoped; ALTER SYSTEM cannot run inside a transaction block.
# Use a database-level default so the new connection picks it up without SET.
psql -c "ALTER DATABASE testdb SET pg_command_fw.block_alter_system = off;"
out=$($SU -c "ALTER SYSTEM SET work_mem = '8MB';" 2>&1)
psql -c "ALTER DATABASE testdb RESET pg_command_fw.block_alter_system;"
if ! echo "$out" | grep -q "not allowed"; then
    pass "superuser ALTER SYSTEM allowed when block_alter_system=off"
else
    fail "superuser ALTER SYSTEM blocked when block_alter_system=off; got: $out"
fi
# Clean up
$SU -c "ALTER SYSTEM RESET work_mem;" 2>/dev/null || true

echo ""
echo "=== COPY PROGRAM ==="

echo ""
echo "--- Test 7: superuser COPY TO PROGRAM is blocked ---"
out=$($SU -c "COPY (SELECT 1) TO PROGRAM 'cat';" 2>&1 || true)
if echo "$out" | grep -q "COPY PROGRAM command is not allowed"; then
    pass "superuser COPY TO PROGRAM blocked"
else
    fail "superuser COPY TO PROGRAM not blocked; got: $out"
fi

echo ""
echo "--- Test 8: non-superuser COPY TO PROGRAM is blocked ---"
out=$(PGPASSWORD=testpass $RU -c "COPY (SELECT 1) TO PROGRAM 'cat';" 2>&1 || true)
if echo "$out" | grep -q "COPY PROGRAM command is not allowed"; then
    pass "non-superuser COPY TO PROGRAM blocked"
else
    fail "non-superuser COPY TO PROGRAM not blocked; got: $out"
fi

echo ""
echo "--- Test 9: block_copy_program=off -> superuser COPY TO PROGRAM allowed ---"
out=$($SU -c "SET pg_command_fw.block_copy_program = off; COPY (SELECT 1) TO PROGRAM 'cat > /dev/null';" 2>&1)
if ! echo "$out" | grep -q "not allowed"; then
    pass "superuser COPY TO PROGRAM allowed when block_copy_program=off"
else
    fail "superuser COPY TO PROGRAM blocked when block_copy_program=off; got: $out"
fi

echo ""
echo "--- Test 10: plain COPY (not PROGRAM) is unaffected by default ---"
out=$($SU -c "COPY (SELECT 1) TO STDOUT;" 2>&1)
if echo "$out" | grep -q "^1$"; then
    pass "plain COPY TO STDOUT unaffected"
else
    fail "plain COPY TO STDOUT affected; got: $out"
fi

echo ""
echo "=== COPY (plain) ==="

echo ""
echo "--- Test 11: block_copy=off (default) -> non-superuser plain COPY allowed ---"
out=$(PGPASSWORD=testpass $RU -c "COPY (SELECT 1) TO STDOUT;" 2>&1)
if ! echo "$out" | grep -q "not allowed"; then
    pass "non-superuser plain COPY allowed when block_copy=off"
else
    fail "non-superuser plain COPY blocked when block_copy=off; got: $out"
fi

echo ""
echo "--- Test 12: block_copy=on -> non-superuser plain COPY blocked ---"
psql -c "ALTER ROLE testuser SET pg_command_fw.block_copy = on;"
out=$(PGPASSWORD=testpass $RU -c "COPY (SELECT 1) TO STDOUT;" 2>&1 || true)
if echo "$out" | grep -q "COPY command is not allowed"; then
    pass "non-superuser plain COPY blocked when block_copy=on"
else
    fail "non-superuser plain COPY not blocked when block_copy=on; got: $out"
fi
psql -c "ALTER ROLE testuser RESET pg_command_fw.block_copy;"

echo ""
echo "--- Test 13: block_copy=on -> superuser plain COPY still allowed ---"
out=$($SU -c "SET pg_command_fw.block_copy = on; COPY (SELECT 1) TO STDOUT;" 2>&1)
if ! echo "$out" | grep -q "not allowed"; then
    pass "superuser plain COPY allowed when block_copy=on"
else
    fail "superuser plain COPY blocked when block_copy=on; got: $out"
fi

echo ""
echo "--- Test 14: block_copy=on + enabled=off -> non-superuser plain COPY allowed ---"
psql -c "ALTER ROLE testuser SET pg_command_fw.block_copy = on;"
psql -c "ALTER ROLE testuser SET pg_command_fw.enabled = off;"
out=$(PGPASSWORD=testpass $RU -c "COPY (SELECT 1) TO STDOUT;" 2>&1)
if ! echo "$out" | grep -q "not allowed"; then
    pass "non-superuser plain COPY allowed when firewall disabled"
else
    fail "non-superuser plain COPY blocked when firewall disabled; got: $out"
fi
psql -c "ALTER ROLE testuser RESET pg_command_fw.block_copy;"
psql -c "ALTER ROLE testuser RESET pg_command_fw.enabled;"

echo ""
echo "=== LOAD ==="

echo ""
echo "--- Test 15: superuser LOAD is blocked ---"
out=$($SU -c "LOAD 'no_such_lib';" 2>&1 || true)
if echo "$out" | grep -q "LOAD command is not allowed"; then
    pass "superuser LOAD blocked"
else
    fail "superuser LOAD not blocked; got: $out"
fi

echo ""
echo "--- Test 16: block_load=off -> LOAD proceeds (may fail for missing lib) ---"
out=$($SU -c "SET pg_command_fw.block_load = off; LOAD 'no_such_lib';" 2>&1 || true)
if ! echo "$out" | grep -q "LOAD command is not allowed"; then
    pass "LOAD not blocked by firewall when block_load=off"
else
    fail "LOAD still blocked by firewall when block_load=off; got: $out"
fi

echo ""
echo "=== DROP TABLE ==="

echo ""
echo "--- Test 17: block_drop_table=off (default) -> non-superuser DROP TABLE allowed ---"
psql -c "CREATE TABLE IF NOT EXISTS drop_test (id int);"
psql -c "GRANT DROP ON TABLE drop_test TO testuser;" 2>/dev/null || \
psql -c "ALTER TABLE drop_test OWNER TO testuser;"
out=$(PGPASSWORD=testpass $RU -c "DROP TABLE IF EXISTS drop_test;" 2>&1)
if ! echo "$out" | grep -q "not allowed"; then
    pass "DROP TABLE allowed when block_drop_table=off"
else
    fail "DROP TABLE blocked when block_drop_table=off; got: $out"
fi

echo ""
echo "--- Test 18: block_drop_table=on -> non-superuser DROP TABLE blocked ---"
psql -c "CREATE TABLE IF NOT EXISTS drop_test (id int);"
psql -c "ALTER TABLE drop_test OWNER TO testuser;"
psql -c "ALTER ROLE testuser SET pg_command_fw.block_drop_table = on;"
out=$(PGPASSWORD=testpass $RU -c "DROP TABLE drop_test;" 2>&1 || true)
if echo "$out" | grep -q "DROP TABLE command is not allowed"; then
    pass "non-superuser DROP TABLE blocked when block_drop_table=on"
else
    fail "non-superuser DROP TABLE not blocked when block_drop_table=on; got: $out"
fi
psql -c "ALTER ROLE testuser RESET pg_command_fw.block_drop_table;"
psql -c "DROP TABLE IF EXISTS drop_test;"

echo ""
echo "--- Test 19: production_schemas set -> non-superuser DROP on production schema blocked ---"
psql -c "CREATE SCHEMA IF NOT EXISTS prod;"
psql -c "CREATE TABLE prod.important (id int);"
psql -c "GRANT USAGE ON SCHEMA prod TO testuser;"
psql -c "ALTER TABLE prod.important OWNER TO testuser;"
psql -c "ALTER ROLE testuser SET pg_command_fw.block_drop_table = on;"
psql -c "ALTER ROLE testuser SET pg_command_fw.production_schemas = 'prod';"
out=$(PGPASSWORD=testpass $RU -c "DROP TABLE prod.important;" 2>&1 || true)
if echo "$out" | grep -q "DROP TABLE command is not allowed"; then
    pass "non-superuser DROP TABLE on production schema blocked"
else
    fail "non-superuser DROP TABLE on production schema not blocked; got: $out"
fi
psql -c "ALTER ROLE testuser RESET pg_command_fw.block_drop_table;"
psql -c "ALTER ROLE testuser RESET pg_command_fw.production_schemas;"
psql -c "DROP TABLE prod.important;"
psql -c "DROP SCHEMA prod;"

echo ""
echo "=== Master switch ==="

echo ""
echo "--- Test 20: enabled=off -> TRUNCATE allowed for non-superuser ---"
psql -c "CREATE TABLE IF NOT EXISTS trunc_master (id int);"
psql -c "GRANT TRUNCATE ON trunc_master TO testuser;"
psql -c "ALTER ROLE testuser SET pg_command_fw.enabled = off;"
out=$(PGPASSWORD=testpass $RU -c "TRUNCATE trunc_master;" 2>&1)
if ! echo "$out" | grep -q "not allowed"; then
    pass "TRUNCATE allowed when firewall disabled"
else
    fail "TRUNCATE blocked when firewall disabled; got: $out"
fi
psql -c "ALTER ROLE testuser RESET pg_command_fw.enabled;"
psql -c "DROP TABLE trunc_master;"

echo ""
echo "=== blocked_roles ==="

echo ""
echo "--- Test 21: superuser in blocked_roles is blocked for TRUNCATE ---"
psql -c "CREATE TABLE IF NOT EXISTS blocked_roles_test (id int);"
out=$($SU -c "SET pg_command_fw.blocked_roles = 'postgres'; TRUNCATE blocked_roles_test;" 2>&1 || true)
if echo "$out" | grep -q "TRUNCATE command is not allowed"; then
    pass "superuser blocked when listed in blocked_roles"
else
    fail "superuser not blocked when listed in blocked_roles; got: $out"
fi
psql -c "DROP TABLE blocked_roles_test;"

echo ""
echo "=== hint GUC ==="

echo ""
echo "--- Test 22: hint is shown in error message ---"
psql -c "CREATE TABLE IF NOT EXISTS hint_test (id int);"
psql -c "GRANT TRUNCATE ON hint_test TO testuser;"
psql -c "ALTER ROLE testuser SET pg_command_fw.hint = 'Contact your DBA';"
out=$(PGPASSWORD=testpass $RU -c "TRUNCATE hint_test;" 2>&1 || true)
if echo "$out" | grep -q "Contact your DBA"; then
    pass "hint is shown in error"
else
    fail "hint not shown in error; got: $out"
fi
psql -c "ALTER ROLE testuser RESET pg_command_fw.hint;"
psql -c "DROP TABLE hint_test;"

echo ""
echo "=== Audit log ==="

echo ""
echo "--- Test 23: allowed TRUNCATE creates audit_log row ---"
psql -c "TRUNCATE command_fw.audit_log;"
psql -c "CREATE TABLE IF NOT EXISTS audit_trunc (id int);"
psql -c "TRUNCATE audit_trunc;"
count=$(q "SELECT count(*) FROM command_fw.audit_log WHERE command_type = 'TRUNCATE' AND NOT blocked;")
if [ "$count" = "1" ]; then
    pass "allowed TRUNCATE creates audit_log row"
else
    fail "expected 1 audit_log row for TRUNCATE, got: $count"
fi
psql -c "DROP TABLE audit_trunc;"

echo ""
echo "--- Test 24: blocked COPY PROGRAM does not persist in audit_log (tx rollback) ---"
psql -c "TRUNCATE command_fw.audit_log;"
$SU -c "COPY (SELECT 1) TO PROGRAM 'cat';" 2>/dev/null || true
count=$(q "SELECT count(*) FROM command_fw.audit_log WHERE blocked;")
if [ "$count" = "0" ]; then
    pass "blocked command does not persist in audit_log (transaction rollback)"
else
    fail "expected 0 audit_log rows for blocked command, got: $count"
fi

echo ""
echo "--- Test 25: audit_log_enabled=off suppresses writes ---"
psql -c "TRUNCATE command_fw.audit_log;"
psql -c "CREATE TABLE IF NOT EXISTS audit_off_test (id int);"
psql -c "SET pg_command_fw.audit_log_enabled = off; TRUNCATE audit_off_test;"
count=$(q "SELECT count(*) FROM command_fw.audit_log;")
if [ "$count" = "0" ]; then
    pass "audit_log_enabled=off suppresses audit writes"
else
    fail "expected 0 audit_log rows when logging disabled, got: $count"
fi
psql -c "DROP TABLE audit_off_test;"

echo ""
echo "--- Test 26: audit_log records command_type and blocked correctly ---"
psql -c "TRUNCATE command_fw.audit_log;"
psql -c "CREATE TABLE IF NOT EXISTS audit_type_test (id int);"
psql -c "TRUNCATE audit_type_test;"
row=$(q "SELECT command_type || '|' || blocked FROM command_fw.audit_log ORDER BY id DESC LIMIT 1;")
if [ "$row" = "TRUNCATE|false" ]; then
    pass "audit_log records command_type=TRUNCATE, blocked=false"
else
    fail "unexpected audit_log content: '$row' (expected 'TRUNCATE|false')"
fi
psql -c "DROP TABLE audit_type_test;"

echo ""
echo "--- Test 27: audit_log records session_user_name ---"
user=$(q "SELECT session_user_name FROM command_fw.audit_log ORDER BY id DESC LIMIT 1;")
if [ "$user" = "postgres" ]; then
    pass "audit_log records session_user_name=postgres"
else
    fail "expected session_user_name='postgres', got: '$user'"
fi

echo ""
echo "=== pg_read_file / pg_read_binary_file / pg_stat_file ==="

echo ""
echo "--- Test 28: superuser pg_read_file is blocked by default ---"
out=$($SU -c "SELECT pg_read_file('PG_VERSION');" 2>&1 || true)
if echo "$out" | grep -q "READ FILE command is not allowed"; then
    pass "superuser pg_read_file blocked by default"
else
    fail "superuser pg_read_file not blocked; got: $out"
fi

echo ""
echo "--- Test 29: non-superuser pg_read_file is blocked by default ---"
out=$(PGPASSWORD=testpass $RU -c "SELECT pg_read_file('PG_VERSION');" 2>&1 || true)
if echo "$out" | grep -q "READ FILE command is not allowed\|must be superuser\|permission denied"; then
    pass "non-superuser pg_read_file blocked"
else
    fail "non-superuser pg_read_file not blocked; got: $out"
fi

echo ""
echo "--- Test 30: superuser pg_read_binary_file is blocked by default ---"
out=$($SU -c "SELECT pg_read_binary_file('PG_VERSION');" 2>&1 || true)
if echo "$out" | grep -q "READ FILE command is not allowed"; then
    pass "superuser pg_read_binary_file blocked by default"
else
    fail "superuser pg_read_binary_file not blocked; got: $out"
fi

echo ""
echo "--- Test 31: superuser pg_stat_file is blocked by default ---"
out=$($SU -c "SELECT pg_stat_file('PG_VERSION');" 2>&1 || true)
if echo "$out" | grep -q "STAT FILE command is not allowed"; then
    pass "superuser pg_stat_file blocked by default"
else
    fail "superuser pg_stat_file not blocked; got: $out"
fi

echo ""
echo "--- Test 32: block_read_file=off -> superuser pg_read_file allowed ---"
out=$($SU -c "SET pg_command_fw.block_read_file = off; SELECT pg_read_file('PG_VERSION');" 2>&1)
if ! echo "$out" | grep -q "not allowed"; then
    pass "superuser pg_read_file allowed when block_read_file=off"
else
    fail "superuser pg_read_file blocked when block_read_file=off; got: $out"
fi

echo ""
echo "--- Test 33: enabled=off -> superuser pg_read_file allowed ---"
out=$($SU -c "SET pg_command_fw.enabled = off; SELECT pg_read_file('PG_VERSION');" 2>&1)
if ! echo "$out" | grep -q "not allowed"; then
    pass "superuser pg_read_file allowed when firewall disabled"
else
    fail "superuser pg_read_file blocked when firewall disabled; got: $out"
fi

echo ""
echo "--- Test 34: blocked pg_read_file recorded in server log, not in audit_log ---"
psql -c "TRUNCATE command_fw.audit_log;"
$SU -c "SELECT pg_read_file('PG_VERSION');" 2>/dev/null || true
count=$(q "SELECT count(*) FROM command_fw.audit_log WHERE blocked AND command_type = 'READ_FILE';")
if [ "$count" = "0" ]; then
    pass "blocked pg_read_file not persisted in audit_log (transaction rollback)"
else
    fail "expected 0 audit_log rows for blocked pg_read_file, got: $count"
fi

echo ""
echo "=== Regular SQL unaffected ==="

echo ""
echo "--- Test 35: SELECT works ---"
result=$(psql -t -A -c "SELECT 42;")
if [ "$result" = "42" ]; then
    pass "Regular SELECT works"
else
    fail "Expected '42', got: '$result'"
fi

echo ""
echo "--- Test 36: CREATE TABLE / INSERT / SELECT work ---"
count=$(psql -t -A <<'SQL' | tail -1
CREATE TEMP TABLE _docker_test (id int);
INSERT INTO _docker_test VALUES (1), (2), (3);
SELECT count(*) FROM _docker_test;
SQL
)
if [ "$count" = "3" ]; then
    pass "CREATE TABLE / INSERT / SELECT work"
else
    fail "Expected count 3, got: '$count'"
fi

echo ""
echo "================================"
echo "Results: $PASS passed, $FAIL failed"
echo "================================"

[ "$FAIL" -eq 0 ]
