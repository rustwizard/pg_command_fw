#![allow(clippy::too_many_arguments)]

use pgrx::datum::DatumWithOid;
use pgrx::guc::{GucContext, GucFlags, GucRegistry, GucSetting};
use pgrx::is_a;
use pgrx::pg_sys;
use pgrx::pg_sys::panic::ErrorReport;
use pgrx::prelude::*;
use std::ffi::CString;

pg_module_magic!();

// Master switch
static FW_ENABLED: GucSetting<bool> = GucSetting::<bool>::new(true);

// Per-category switches
// TRUNCATE: blocked for non-superusers.
static BLOCK_TRUNCATE: GucSetting<bool> = GucSetting::<bool>::new(true);
// DROP TABLE: blocked for non-superusers in production schemas (opt-in).
static BLOCK_DROP_TABLE: GucSetting<bool> = GucSetting::<bool>::new(false);
// Comma-separated list of production schemas for DROP TABLE checks.
// When empty and block_drop_table=on, ALL DROP TABLE is blocked for non-superusers.
static PRODUCTION_SCHEMAS: GucSetting<Option<CString>> = GucSetting::<Option<CString>>::new(None);
// ALTER SYSTEM: blocked for all users including superusers.
static BLOCK_ALTER_SYSTEM: GucSetting<bool> = GucSetting::<bool>::new(true);
// LOAD: blocked for all users including superusers.
static BLOCK_LOAD: GucSetting<bool> = GucSetting::<bool>::new(true);
// COPY TO/FROM PROGRAM: blocked for all users including superusers.
static BLOCK_COPY_PROGRAM: GucSetting<bool> = GucSetting::<bool>::new(true);
// COPY (plain, non-PROGRAM): blocked for non-superusers (opt-in).
static BLOCK_COPY: GucSetting<bool> = GucSetting::<bool>::new(false);
// pg_read_file / pg_read_binary_file / pg_stat_file: blocked for all users including superusers.
static BLOCK_READ_FILE: GucSetting<bool> = GucSetting::<bool>::new(true);

// Cross-category settings
// Comma-separated list of roles that are always blocked, including superusers.
static BLOCKED_ROLES: GucSetting<Option<CString>> = GucSetting::<Option<CString>>::new(None);
// Optional hint message shown to users when their command is blocked.
static HINT: GucSetting<Option<CString>> = GucSetting::<Option<CString>>::new(None);
// Write every intercepted event to pg_command_fw.audit_log via SPI.
// NOTE: blocked events are written before ERROR is raised and will be rolled back
// when the transaction aborts.  The server LOG line is authoritative for blocked events.
static AUDIT_LOG_ENABLED: GucSetting<bool> = GucSetting::<bool>::new(true);

static mut PREV_PROCESS_UTILITY_HOOK: pg_sys::ProcessUtility_hook_type = None;
static mut PREV_POST_PARSE_ANALYZE_HOOK: pg_sys::post_parse_analyze_hook_type = None;

// Hook argument bundle
struct ProcessUtilityArgs {
    pstmt: *mut pg_sys::PlannedStmt,
    query_string: *const std::os::raw::c_char,
    #[cfg(not(feature = "pg13"))]
    read_only_tree: bool,
    context: pg_sys::ProcessUtilityContext::Type,
    params: pg_sys::ParamListInfo,
    query_env: *mut pg_sys::QueryEnvironment,
    dest: *mut pg_sys::DestReceiver,
    qc: *mut pg_sys::QueryCompletion,
}

// Firewall decision
struct FirewallDecision {
    /// Command category label written to the audit log.
    command_type: &'static str,
    /// Schema name; populated for DROP_TABLE when a production schema matches.
    target_schema: Option<String>,
    /// Target object; populated for LOAD (library filename).
    target_object: Option<String>,
    /// None → command matched but is allowed; Some → reason why it was blocked.
    block_reason: Option<&'static str>,
}

// Firewall logic
/// Returns None if the node is not a category we police.
/// Returns Some(decision) for every matched category (blocked or not).
unsafe fn check_firewall(node: *mut pg_sys::Node, current_user: &str) -> Option<FirewallDecision> {
    if !FW_ENABLED.get() {
        return None;
    }

    let in_blocked_list = is_role_blocked(current_user);
    let is_super = pg_sys::superuser();

    // COPY TO/FROM PROGRAM or plain COPY
    if is_a(node, pg_sys::NodeTag::T_CopyStmt) {
        let copy_stmt = node as *mut pg_sys::CopyStmt;
        if (*copy_stmt).is_program {
            let block_reason = if in_blocked_list {
                Some("role_listed")
            } else if BLOCK_COPY_PROGRAM.get() {
                Some("copy_program")
            } else {
                None
            };
            return Some(FirewallDecision {
                command_type: "COPY_PROGRAM",
                target_schema: None,
                target_object: None,
                block_reason,
            });
        }
        // Plain COPY (to/from file or stdout)
        if !BLOCK_COPY.get() && !in_blocked_list {
            return None;
        }
        let block_reason = if in_blocked_list {
            Some("role_listed")
        } else if BLOCK_COPY.get() && !is_super {
            Some("copy")
        } else {
            None
        };
        return Some(FirewallDecision {
            command_type: "COPY",
            target_schema: None,
            target_object: None,
            block_reason,
        });
    }

    // ALTER SYSTEM
    if is_a(node, pg_sys::NodeTag::T_AlterSystemStmt) {
        let block_reason = if in_blocked_list {
            Some("role_listed")
        } else if BLOCK_ALTER_SYSTEM.get() {
            Some("alter_system")
        } else {
            None
        };
        return Some(FirewallDecision {
            command_type: "ALTER_SYSTEM",
            target_schema: None,
            target_object: None,
            block_reason,
        });
    }

    // LOAD
    if is_a(node, pg_sys::NodeTag::T_LoadStmt) {
        let load_stmt = node as *mut pg_sys::LoadStmt;
        let filename = if !(*load_stmt).filename.is_null() {
            Some(
                std::ffi::CStr::from_ptr((*load_stmt).filename)
                    .to_string_lossy()
                    .into_owned(),
            )
        } else {
            None
        };
        let block_reason = if in_blocked_list {
            Some("role_listed")
        } else if BLOCK_LOAD.get() {
            Some("load")
        } else {
            None
        };
        return Some(FirewallDecision {
            command_type: "LOAD",
            target_schema: None,
            target_object: filename,
            block_reason,
        });
    }

    // TRUNCATE (non-superusers)
    if is_a(node, pg_sys::NodeTag::T_TruncateStmt) {
        let block_reason = if in_blocked_list {
            Some("role_listed")
        } else if BLOCK_TRUNCATE.get() && !is_super {
            Some("truncate_non_superuser")
        } else {
            None
        };
        return Some(FirewallDecision {
            command_type: "TRUNCATE",
            target_schema: None,
            target_object: None,
            block_reason,
        });
    }

    // DROP TABLE (non-superusers, optionally scoped to production schemas)
    if is_a(node, pg_sys::NodeTag::T_DropStmt) {
        let drop_stmt = node as *mut pg_sys::DropStmt;
        if (*drop_stmt).removeType != pg_sys::ObjectType::OBJECT_TABLE {
            return None;
        }

        let (blocked_schema, block_reason) =
            compute_drop_table_decision(drop_stmt, in_blocked_list, is_super);

        return Some(FirewallDecision {
            command_type: "DROP_TABLE",
            target_schema: blocked_schema,
            target_object: None,
            block_reason,
        });
    }

    None
}

/// Compute the DROP TABLE block decision and the schema that triggered it.
unsafe fn compute_drop_table_decision(
    drop_stmt: *mut pg_sys::DropStmt,
    in_blocked_list: bool,
    is_super: bool,
) -> (Option<String>, Option<&'static str>) {
    if in_blocked_list {
        return (None, Some("role_listed"));
    }
    if !BLOCK_DROP_TABLE.get() || is_super {
        return (None, None);
    }

    let prod_schemas_raw = PRODUCTION_SCHEMAS
        .get()
        .and_then(|cstr| cstr.to_str().ok().map(|s| s.to_owned()));

    match prod_schemas_raw {
        // No production_schemas configured → block all DROP TABLE.
        None => (None, Some("drop_production_table")),
        Some(ref s) if s.is_empty() => (None, Some("drop_production_table")),
        Some(schemas_str) => {
            // Block only when an explicit schema-qualified name matches.
            let prod_list: Vec<&str> = schemas_str.split(',').map(str::trim).collect();
            let explicit_schemas = extract_schemas_from_drop_stmt(drop_stmt);
            for schema in explicit_schemas {
                if prod_list.contains(&schema.as_str()) {
                    return (Some(schema), Some("drop_production_table"));
                }
            }
            (None, None)
        }
    }
}

/// Collect the explicitly schema-qualified names from a DROP TABLE statement.
/// Unqualified names (single-element inner list) are skipped; name resolution
/// via search_path is deferred to a future version.
unsafe fn extract_schemas_from_drop_stmt(drop_stmt: *mut pg_sys::DropStmt) -> Vec<String> {
    let mut schemas = Vec::new();
    let objects = (*drop_stmt).objects;
    if objects.is_null() {
        return schemas;
    }
    let n = (*objects).length as isize;
    let cells = (*objects).elements;
    for i in 0..n {
        // Each cell is a pointer to an inner List of name parts.
        let inner_list = (*cells.offset(i)).ptr_value as *mut pg_sys::List;
        if inner_list.is_null() || (*inner_list).length < 2 {
            continue;
        }
        // First element of the inner list is the schema name.
        let schema_cell_ptr = (*(*inner_list).elements.offset(0)).ptr_value;
        if schema_cell_ptr.is_null() {
            continue;
        }
        if let Some(name) = extract_string_node(schema_cell_ptr) {
            schemas.push(name);
        }
    }
    schemas
}

/// Extract the string value from a T_String (PG14+) or T_String/Value (PG13) node pointer.
#[cfg(not(feature = "pg13"))]
unsafe fn extract_string_node(ptr: *mut std::os::raw::c_void) -> Option<String> {
    let s = ptr as *mut pg_sys::String;
    if (*s).sval.is_null() {
        return None;
    }
    std::ffi::CStr::from_ptr((*s).sval)
        .to_str()
        .ok()
        .map(|v| v.to_owned())
}

#[cfg(feature = "pg13")]
unsafe fn extract_string_node(ptr: *mut std::os::raw::c_void) -> Option<String> {
    let v = ptr as *mut pg_sys::Value;
    let str_ptr = (*v).val.str_;
    if str_ptr.is_null() {
        return None;
    }
    std::ffi::CStr::from_ptr(str_ptr)
        .to_str()
        .ok()
        .map(|v| v.to_owned())
}

// Returns the audit log command_type label if `fn_oid` resolves to one of the
// file-access functions we block, or `None` otherwise.
unsafe fn file_access_command_type(fn_oid: pg_sys::Oid) -> Option<&'static str> {
    let tuple = pg_sys::SearchSysCache1(
        pg_sys::SysCacheIdentifier::PROCOID as _,
        pg_sys::Datum::from(fn_oid),
    );
    if tuple.is_null() {
        return None;
    }
    let proc_form = pg_sys::GETSTRUCT(tuple) as *mut pg_sys::FormData_pg_proc;
    let name_cstr = std::ffi::CStr::from_ptr((*proc_form).proname.data.as_ptr());
    let name = name_cstr.to_str().unwrap_or("");
    let result = match name {
        "pg_read_file" | "pg_read_binary_file" => Some("READ_FILE"),
        "pg_stat_file" => Some("STAT_FILE"),
        _ => None,
    };
    pg_sys::ReleaseSysCache(tuple);
    result
}

// Thin wrappers around expression_tree_walker / query_tree_walker.
// PG16 renamed both to *_impl (they became macros in the headers), so the
// old symbol names are only available as real exports in PG15.
type WalkerFn = Option<unsafe extern "C-unwind" fn(*mut pg_sys::Node, *mut std::ffi::c_void) -> bool>;

#[cfg(feature = "pg15")]
extern "C" {
    fn expression_tree_walker(
        node: *mut pg_sys::Node,
        walker: WalkerFn,
        context: *mut std::ffi::c_void,
    ) -> bool;
    fn query_tree_walker(
        query: *mut pg_sys::Query,
        walker: WalkerFn,
        context: *mut std::ffi::c_void,
        flags: std::ffi::c_int,
    ) -> bool;
}

#[inline]
unsafe fn expr_tree_walk(node: *mut pg_sys::Node, walker: WalkerFn, ctx: *mut std::ffi::c_void) -> bool {
    #[cfg(feature = "pg15")]
    { expression_tree_walker(node, walker, ctx) }
    #[cfg(not(feature = "pg15"))]
    { pg_sys::expression_tree_walker_impl(node, walker, ctx) }
}

#[inline]
unsafe fn query_tree_walk(query: *mut pg_sys::Query, walker: WalkerFn, ctx: *mut std::ffi::c_void) -> bool {
    #[cfg(feature = "pg15")]
    { query_tree_walker(query, walker, ctx, 0) }
    #[cfg(not(feature = "pg15"))]
    { pg_sys::query_tree_walker_impl(query, walker, ctx, 0) }
}

// Walker callback: returns true (stop) when a blocked FuncExpr is found.
// Stores the command_type label in the context pointer.
unsafe extern "C-unwind" fn blocked_func_walker(
    node: *mut pg_sys::Node,
    context: *mut std::ffi::c_void,
) -> bool {
    if node.is_null() {
        return false;
    }
    if is_a(node, pg_sys::NodeTag::T_FuncExpr) {
        let fe = node as *mut pg_sys::FuncExpr;
        if let Some(ct) = file_access_command_type((*fe).funcid) {
            *(context as *mut Option<&'static str>) = Some(ct);
            return true;
        }
    }
    // Descend into subqueries (SubLink, RTE_SUBQUERY, etc.)
    if is_a(node, pg_sys::NodeTag::T_Query) {
        return query_tree_walk(node as *mut pg_sys::Query, Some(blocked_func_walker), context);
    }
    expr_tree_walk(node, Some(blocked_func_walker), context)
}

// Scan the entire query tree for any call to a blocked file-access function.
unsafe fn query_find_blocked_func(query: *mut pg_sys::Query) -> Option<&'static str> {
    let mut result: Option<&'static str> = None;
    let ctx = &mut result as *mut Option<&'static str> as *mut std::ffi::c_void;
    query_tree_walk(query, Some(blocked_func_walker), ctx);
    result
}

// post_parse_analyze_hook trampoline (PG14+ signature: includes jstate)
#[pg_guard]
unsafe extern "C-unwind" fn post_parse_analyze_hook_fn(
    pstate: *mut pg_sys::ParseState,
    query: *mut pg_sys::Query,
    jstate: *mut pg_sys::JumbleState,
) {
    if FW_ENABLED.get() && BLOCK_READ_FILE.get() && !query.is_null() {
        if let Some(command_type) = query_find_blocked_func(query) {
            let current_user = get_current_username().unwrap_or_else(|| "unknown".to_string());
            let session_user = get_session_username().unwrap_or_else(|| "unknown".to_string());
            let in_blocked_list = is_role_blocked(&current_user);
            let block_reason = if in_blocked_list {
                Some("role_listed")
            } else {
                Some("read_file")
            };
            let query_text = if !pg_sys::debug_query_string.is_null() {
                std::ffi::CStr::from_ptr(pg_sys::debug_query_string)
                    .to_str()
                    .unwrap_or("<non-utf8 query>")
            } else {
                "<unknown>"
            };
            write_audit_log(
                &session_user,
                &current_user,
                query_text,
                command_type,
                None,
                None,
                true,
                block_reason,
            );
            let msg = format!("{} command is not allowed", command_type.replace('_', " "));
            let hint = HINT
                .get()
                .and_then(|cstr| cstr.to_str().ok().map(str::to_owned));
            let mut report =
                ErrorReport::new(PgSqlErrorCode::ERRCODE_INSUFFICIENT_PRIVILEGE, msg, "");
            if let Some(h) = hint {
                report = report.set_hint(h);
            }
            report.report(PgLogLevel::ERROR);
        }
    }

    if let Some(prev) = PREV_POST_PARSE_ANALYZE_HOOK {
        prev(pstate, query, jstate);
    }
}

// Role helper
fn is_role_blocked(current_user: &str) -> bool {
    BLOCKED_ROLES
        .get()
        .and_then(|cstr| cstr.to_str().ok().map(|s| s.to_owned()))
        .map(|list| list.split(',').map(str::trim).any(|r| r == current_user))
        .unwrap_or(false)
}

// Core hook function
unsafe fn command_firewall_process_utility(args: ProcessUtilityArgs) {
    let node = (*args.pstmt).utilityStmt;

    if !node.is_null() {
        let current_user = get_current_username().unwrap_or_else(|| "unknown".to_string());
        let session_user = get_session_username().unwrap_or_else(|| "unknown".to_string());
        let query_text = std::ffi::CStr::from_ptr(args.query_string)
            .to_str()
            .unwrap_or("<non-utf8 query>");

        if let Some(decision) = check_firewall(node, &current_user) {
            let blocked = decision.block_reason.is_some();

            write_audit_log(
                &session_user,
                &current_user,
                query_text,
                decision.command_type,
                decision.target_schema.as_deref(),
                decision.target_object.as_deref(),
                blocked,
                decision.block_reason,
            );

            if blocked {
                pgrx::log!(
                    "blocked {} user={:?} reason={:?}",
                    decision.command_type,
                    current_user,
                    decision.block_reason.unwrap_or(""),
                );
                let msg = format!(
                    "{} command is not allowed",
                    decision.command_type.replace('_', " ")
                );
                let hint = HINT
                    .get()
                    .and_then(|cstr| cstr.to_str().ok().map(str::to_owned));
                let mut report =
                    ErrorReport::new(PgSqlErrorCode::ERRCODE_INSUFFICIENT_PRIVILEGE, msg, "");
                if let Some(h) = hint {
                    report = report.set_hint(h);
                }
                report.report(PgLogLevel::ERROR);
            }
        }
    }

    #[cfg(feature = "pg13")]
    match PREV_PROCESS_UTILITY_HOOK {
        Some(prev) => prev(
            args.pstmt,
            args.query_string,
            args.context,
            args.params,
            args.query_env,
            args.dest,
            args.qc,
        ),
        None => pg_sys::standard_ProcessUtility(
            args.pstmt,
            args.query_string,
            args.context,
            args.params,
            args.query_env,
            args.dest,
            args.qc,
        ),
    }

    #[cfg(not(feature = "pg13"))]
    match PREV_PROCESS_UTILITY_HOOK {
        Some(prev) => prev(
            args.pstmt,
            args.query_string,
            args.read_only_tree,
            args.context,
            args.params,
            args.query_env,
            args.dest,
            args.qc,
        ),
        None => pg_sys::standard_ProcessUtility(
            args.pstmt,
            args.query_string,
            args.read_only_tree,
            args.context,
            args.params,
            args.query_env,
            args.dest,
            args.qc,
        ),
    }
}

// Audit log
/// Write one row to pg_command_fw.audit_log.  All errors are silently
/// swallowed so a missing table (library loaded before CREATE EXTENSION) or
/// any SPI problem never interrupts the firewall logic.
fn write_audit_log(
    session_user: &str,
    current_user: &str,
    query_text: &str,
    command_type: &str,
    target_schema: Option<&str>,
    target_object: Option<&str>,
    blocked: bool,
    block_reason: Option<&str>,
) {
    if !AUDIT_LOG_ENABLED.get() {
        return;
    }

    PgTryBuilder::new(move || {
        Spi::connect_mut(|client| {
            let args = [
                DatumWithOid::from(session_user),
                DatumWithOid::from(current_user),
                DatumWithOid::from(query_text),
                DatumWithOid::from(command_type),
                DatumWithOid::from(target_schema),
                DatumWithOid::from(target_object),
                DatumWithOid::from(blocked),
                DatumWithOid::from(block_reason),
            ];
            let _ = client.update(
                "INSERT INTO command_fw.audit_log \
                 (session_user_name, current_user_name, query_text, command_type, \
                  target_schema, target_object, client_addr, application_name, \
                  blocked, block_reason) \
                 VALUES ($1, $2, $3, $4, $5, $6, \
                         inet_client_addr(), \
                         current_setting('application_name', true), \
                         $7, $8)",
                None,
                &args,
            );
        });
    })
    .catch_others(|_| ())
    .execute();
}

// Hook trampolines
#[pg_guard]
#[cfg(feature = "pg13")]
unsafe extern "C-unwind" fn hook_trampoline(
    pstmt: *mut pg_sys::PlannedStmt,
    query_string: *const std::os::raw::c_char,
    context: pg_sys::ProcessUtilityContext::Type,
    params: pg_sys::ParamListInfo,
    query_env: *mut pg_sys::QueryEnvironment,
    dest: *mut pg_sys::DestReceiver,
    qc: *mut pg_sys::QueryCompletion,
) {
    unsafe {
        command_firewall_process_utility(ProcessUtilityArgs {
            pstmt,
            query_string,
            context,
            params,
            query_env,
            dest,
            qc,
        });
    }
}

#[pg_guard]
#[cfg(not(feature = "pg13"))]
unsafe extern "C-unwind" fn hook_trampoline(
    pstmt: *mut pg_sys::PlannedStmt,
    query_string: *const std::os::raw::c_char,
    read_only_tree: bool,
    context: pg_sys::ProcessUtilityContext::Type,
    params: pg_sys::ParamListInfo,
    query_env: *mut pg_sys::QueryEnvironment,
    dest: *mut pg_sys::DestReceiver,
    qc: *mut pg_sys::QueryCompletion,
) {
    unsafe {
        command_firewall_process_utility(ProcessUtilityArgs {
            pstmt,
            query_string,
            read_only_tree,
            context,
            params,
            query_env,
            dest,
            qc,
        });
    }
}

// Extension init
#[pg_guard]
pub extern "C-unwind" fn _PG_init() {
    GucRegistry::define_bool_guc(
        c"pg_command_fw.enabled",
        c"Master switch for the command firewall",
        c"When on (default), the firewall intercepts and potentially blocks DDL/utility \
          commands according to the per-category settings.  Set to off to disable all \
          checks without unloading the extension.",
        &FW_ENABLED,
        GucContext::Suset,
        GucFlags::default(),
    );

    GucRegistry::define_bool_guc(
        c"pg_command_fw.block_truncate",
        c"Block TRUNCATE for non-superusers",
        c"When on (default), TRUNCATE is blocked for all non-superusers.  Superusers \
          are exempt unless listed in pg_command_fw.blocked_roles.",
        &BLOCK_TRUNCATE,
        GucContext::Suset,
        GucFlags::default(),
    );

    GucRegistry::define_bool_guc(
        c"pg_command_fw.block_drop_table",
        c"Block DROP TABLE for non-superusers (opt-in)",
        c"When on, DROP TABLE is blocked for non-superusers.  If \
          pg_command_fw.production_schemas is set, only drops targeting those schemas \
          are blocked; otherwise all DROP TABLE is blocked.",
        &BLOCK_DROP_TABLE,
        GucContext::Suset,
        GucFlags::default(),
    );

    GucRegistry::define_string_guc(
        c"pg_command_fw.production_schemas",
        c"Comma-separated list of production schemas for DROP TABLE checks",
        c"When set and block_drop_table=on, only DROP TABLE commands that reference an \
          explicitly schema-qualified table in one of these schemas are blocked.  \
          Unqualified names are not resolved and will not be matched.  \
          When empty (default) and block_drop_table=on, all DROP TABLE is blocked.",
        &PRODUCTION_SCHEMAS,
        GucContext::Suset,
        GucFlags::default(),
    );

    GucRegistry::define_bool_guc(
        c"pg_command_fw.block_alter_system",
        c"Block ALTER SYSTEM for all users including superusers",
        c"When on (default), ALTER SYSTEM is blocked for every role including \
          superusers.  This prevents runtime changes to postgresql.conf via SQL.",
        &BLOCK_ALTER_SYSTEM,
        GucContext::Suset,
        GucFlags::default(),
    );

    GucRegistry::define_bool_guc(
        c"pg_command_fw.block_load",
        c"Block LOAD for all users including superusers",
        c"When on (default), LOAD (dynamic library loading) is blocked for every role \
          including superusers.",
        &BLOCK_LOAD,
        GucContext::Suset,
        GucFlags::default(),
    );

    GucRegistry::define_bool_guc(
        c"pg_command_fw.block_copy_program",
        c"Block COPY TO/FROM PROGRAM for all users including superusers",
        c"When on (default), COPY TO/FROM PROGRAM is blocked for every role including \
          superusers.  This prevents shell command execution via COPY.",
        &BLOCK_COPY_PROGRAM,
        GucContext::Suset,
        GucFlags::default(),
    );

    GucRegistry::define_bool_guc(
        c"pg_command_fw.block_copy",
        c"Block plain COPY (non-PROGRAM) for non-superusers (opt-in)",
        c"When on, COPY TO/FROM file or stdout is blocked for non-superusers.  \
          Superusers are exempt unless listed in pg_command_fw.blocked_roles.",
        &BLOCK_COPY,
        GucContext::Suset,
        GucFlags::default(),
    );

    GucRegistry::define_bool_guc(
        c"pg_command_fw.block_read_file",
        c"Block pg_read_file / pg_read_binary_file / pg_stat_file for all users",
        c"When on (default), calls to pg_read_file(), pg_read_binary_file(), and \
          pg_stat_file() are blocked for every role including superusers.  These \
          functions allow reading arbitrary server-side files and represent the same \
          data-exfiltration threat as COPY TO FILE.",
        &BLOCK_READ_FILE,
        GucContext::Suset,
        GucFlags::default(),
    );

    GucRegistry::define_string_guc(
        c"pg_command_fw.blocked_roles",
        c"Comma-separated list of roles always blocked from firewall-governed commands",
        c"Roles in this list are blocked from any firewall-governed command regardless \
          of superuser status or per-category settings.",
        &BLOCKED_ROLES,
        GucContext::Suset,
        GucFlags::default(),
    );

    GucRegistry::define_string_guc(
        c"pg_command_fw.hint",
        c"Custom hint shown when a command is blocked",
        c"When set, this message is appended as a HINT to the error raised when a \
          command is blocked (e.g. 'Contact your DBA to request access').",
        &HINT,
        GucContext::Suset,
        GucFlags::default(),
    );

    GucRegistry::define_bool_guc(
        c"pg_command_fw.audit_log_enabled",
        c"Write intercepted events to pg_command_fw.audit_log",
        c"When on (default), every intercepted command is recorded in \
          pg_command_fw.audit_log via SPI.  Blocked events are best-effort: the \
          INSERT is rolled back when ERROR aborts the transaction, so the server log \
          is authoritative for blocked events.  Set to off to disable table writes.",
        &AUDIT_LOG_ENABLED,
        GucContext::Suset,
        GucFlags::default(),
    );

    unsafe {
        PREV_PROCESS_UTILITY_HOOK = pg_sys::ProcessUtility_hook;
        pg_sys::ProcessUtility_hook = Some(hook_trampoline);

        PREV_POST_PARSE_ANALYZE_HOOK = pg_sys::post_parse_analyze_hook;
        pg_sys::post_parse_analyze_hook = Some(post_parse_analyze_hook_fn);
    }
}

// User helper functions
fn get_current_username() -> Option<String> {
    unsafe {
        let user_oid = pg_sys::GetUserId();
        let name_ptr = pg_sys::GetUserNameFromId(user_oid, true);
        if name_ptr.is_null() {
            None
        } else {
            Some(
                std::ffi::CStr::from_ptr(name_ptr)
                    .to_string_lossy()
                    .into_owned(),
            )
        }
    }
}

fn get_session_username() -> Option<String> {
    unsafe {
        let user_oid = pg_sys::GetSessionUserId();
        let name_ptr = pg_sys::GetUserNameFromId(user_oid, true);
        if name_ptr.is_null() {
            None
        } else {
            Some(
                std::ffi::CStr::from_ptr(name_ptr)
                    .to_string_lossy()
                    .into_owned(),
            )
        }
    }
}

extension_sql_file!(".././sql/hooks.sql");

// Test harness
#[cfg(test)]
pub mod pg_test {
    pub fn setup(_options: Vec<&str>) {}

    pub fn postgresql_conf_options() -> Vec<&'static str> {
        vec!["shared_preload_libraries = 'pg_command_fw'"]
    }
}

#[cfg(any(test, feature = "pg_test"))]
#[pg_schema]
mod tests {
    use pgrx::prelude::*;

    fn show(guc: &str) -> String {
        Spi::get_one::<String>(&format!("SHOW {guc}"))
            .unwrap()
            .unwrap_or_default()
    }

    // Pass-through: DML/non-firewalled DDL
    #[pg_test]
    fn test_select_allowed() {
        let val = Spi::get_one::<i32>("SELECT 42").unwrap();
        assert_eq!(val, Some(42));
    }

    #[pg_test]
    fn test_insert_update_delete_allowed() {
        Spi::run("CREATE TEMP TABLE _fw_dml (id int, v text)").unwrap();
        Spi::run("INSERT INTO _fw_dml VALUES (1, 'a'), (2, 'b')").unwrap();
        Spi::run("UPDATE _fw_dml SET v = 'x' WHERE id = 1").unwrap();
        Spi::run("DELETE FROM _fw_dml WHERE id = 2").unwrap();
        let count = Spi::get_one::<i64>("SELECT count(*) FROM _fw_dml")
            .unwrap()
            .unwrap();
        assert_eq!(count, 1);
        Spi::run("DROP TABLE _fw_dml").unwrap();
    }

    #[pg_test]
    fn test_create_index_allowed() {
        Spi::run("CREATE TEMP TABLE _fw_idx (id int)").unwrap();
        Spi::run("CREATE INDEX ON _fw_idx (id)").unwrap();
        Spi::run("DROP TABLE _fw_idx").unwrap();
    }

    // GUC defaults
    #[pg_test]
    fn test_guc_enabled_default_on() {
        assert_eq!(show("pg_command_fw.enabled"), "on");
    }

    #[pg_test]
    fn test_guc_block_truncate_default_on() {
        assert_eq!(show("pg_command_fw.block_truncate"), "on");
    }

    #[pg_test]
    fn test_guc_block_drop_table_default_off() {
        assert_eq!(show("pg_command_fw.block_drop_table"), "off");
    }

    #[pg_test]
    fn test_guc_production_schemas_default_empty() {
        assert_eq!(show("pg_command_fw.production_schemas"), "");
    }

    #[pg_test]
    fn test_guc_block_alter_system_default_on() {
        assert_eq!(show("pg_command_fw.block_alter_system"), "on");
    }

    #[pg_test]
    fn test_guc_block_load_default_on() {
        assert_eq!(show("pg_command_fw.block_load"), "on");
    }

    #[pg_test]
    fn test_guc_block_copy_program_default_on() {
        assert_eq!(show("pg_command_fw.block_copy_program"), "on");
    }

    #[pg_test]
    fn test_guc_blocked_roles_default_empty() {
        assert_eq!(show("pg_command_fw.blocked_roles"), "");
    }

    #[pg_test]
    fn test_guc_audit_log_enabled_default_on() {
        assert_eq!(show("pg_command_fw.audit_log_enabled"), "on");
    }

    // GUC round-trips
    #[pg_test]
    fn test_guc_enabled_roundtrip() {
        Spi::run("SET pg_command_fw.enabled = off").unwrap();
        assert_eq!(show("pg_command_fw.enabled"), "off");
        Spi::run("SET pg_command_fw.enabled = on").unwrap();
        assert_eq!(show("pg_command_fw.enabled"), "on");
    }

    #[pg_test]
    fn test_guc_block_truncate_roundtrip() {
        Spi::run("SET pg_command_fw.block_truncate = off").unwrap();
        assert_eq!(show("pg_command_fw.block_truncate"), "off");
        Spi::run("SET pg_command_fw.block_truncate = on").unwrap();
        assert_eq!(show("pg_command_fw.block_truncate"), "on");
    }

    #[pg_test]
    fn test_guc_block_drop_table_roundtrip() {
        Spi::run("SET pg_command_fw.block_drop_table = on").unwrap();
        assert_eq!(show("pg_command_fw.block_drop_table"), "on");
        Spi::run("SET pg_command_fw.block_drop_table = off").unwrap();
        assert_eq!(show("pg_command_fw.block_drop_table"), "off");
    }

    #[pg_test]
    fn test_guc_production_schemas_roundtrip() {
        Spi::run("SET pg_command_fw.production_schemas = 'prod, main'").unwrap();
        assert_eq!(show("pg_command_fw.production_schemas"), "prod, main");
        Spi::run("RESET pg_command_fw.production_schemas").unwrap();
        assert_eq!(show("pg_command_fw.production_schemas"), "");
    }

    #[pg_test]
    fn test_guc_block_alter_system_roundtrip() {
        Spi::run("SET pg_command_fw.block_alter_system = off").unwrap();
        assert_eq!(show("pg_command_fw.block_alter_system"), "off");
        Spi::run("SET pg_command_fw.block_alter_system = on").unwrap();
        assert_eq!(show("pg_command_fw.block_alter_system"), "on");
    }

    #[pg_test]
    fn test_guc_block_load_roundtrip() {
        Spi::run("SET pg_command_fw.block_load = off").unwrap();
        assert_eq!(show("pg_command_fw.block_load"), "off");
        Spi::run("SET pg_command_fw.block_load = on").unwrap();
        assert_eq!(show("pg_command_fw.block_load"), "on");
    }

    #[pg_test]
    fn test_guc_block_copy_program_roundtrip() {
        Spi::run("SET pg_command_fw.block_copy_program = off").unwrap();
        assert_eq!(show("pg_command_fw.block_copy_program"), "off");
        Spi::run("SET pg_command_fw.block_copy_program = on").unwrap();
        assert_eq!(show("pg_command_fw.block_copy_program"), "on");
    }

    #[pg_test]
    fn test_guc_block_copy_default_off() {
        assert_eq!(show("pg_command_fw.block_copy"), "off");
    }

    #[pg_test]
    fn test_guc_block_copy_roundtrip() {
        Spi::run("SET pg_command_fw.block_copy = on").unwrap();
        assert_eq!(show("pg_command_fw.block_copy"), "on");
        Spi::run("SET pg_command_fw.block_copy = off").unwrap();
        assert_eq!(show("pg_command_fw.block_copy"), "off");
    }

    #[pg_test]
    fn test_guc_blocked_roles_roundtrip() {
        Spi::run("SET pg_command_fw.blocked_roles = 'alice, bob'").unwrap();
        assert_eq!(show("pg_command_fw.blocked_roles"), "alice, bob");
        Spi::run("RESET pg_command_fw.blocked_roles").unwrap();
        assert_eq!(show("pg_command_fw.blocked_roles"), "");
    }

    #[pg_test]
    fn test_guc_audit_log_enabled_roundtrip() {
        Spi::run("SET pg_command_fw.audit_log_enabled = off").unwrap();
        assert_eq!(show("pg_command_fw.audit_log_enabled"), "off");
        Spi::run("SET pg_command_fw.audit_log_enabled = on").unwrap();
        assert_eq!(show("pg_command_fw.audit_log_enabled"), "on");
    }

    #[pg_test]
    fn test_guc_block_read_file_default_on() {
        assert_eq!(show("pg_command_fw.block_read_file"), "on");
    }

    #[pg_test]
    fn test_guc_block_read_file_roundtrip() {
        Spi::run("SET pg_command_fw.block_read_file = off").unwrap();
        assert_eq!(show("pg_command_fw.block_read_file"), "off");
        Spi::run("SET pg_command_fw.block_read_file = on").unwrap();
        assert_eq!(show("pg_command_fw.block_read_file"), "on");
    }

    // Audit log table structure
    #[pg_test]
    fn test_audit_log_table_exists() {
        let count = Spi::get_one::<i64>(
            "SELECT count(*) FROM information_schema.tables \
             WHERE table_schema = 'pg_command_fw' AND table_name = 'audit_log'",
        )
        .unwrap()
        .unwrap();
        assert_eq!(count, 1);
    }

    #[pg_test]
    fn test_audit_log_expected_columns_exist() {
        let expected = [
            "id",
            "ts",
            "session_user_name",
            "current_user_name",
            "query_text",
            "command_type",
            "target_schema",
            "target_object",
            "client_addr",
            "application_name",
            "blocked",
            "block_reason",
        ];
        for col in expected {
            let found = Spi::get_one::<i64>(&format!(
                "SELECT count(*) FROM information_schema.columns \
                 WHERE table_schema = 'pg_command_fw' \
                   AND table_name   = 'audit_log' \
                   AND column_name  = '{col}'"
            ))
            .unwrap()
            .unwrap();
            assert_eq!(found, 1, "column '{col}' missing from audit_log");
        }
    }

    #[pg_test]
    fn test_audit_log_is_writable() {
        Spi::run(
            "INSERT INTO command_fw.audit_log \
             (session_user_name, current_user_name, query_text, \
              command_type, blocked) \
             VALUES ('u', 'u', 'TRUNCATE t', 'TRUNCATE', false)",
        )
        .unwrap();
        let count = Spi::get_one::<i64>(
            "SELECT count(*) FROM command_fw.audit_log \
             WHERE query_text = 'TRUNCATE t'",
        )
        .unwrap()
        .unwrap();
        assert_eq!(count, 1);
        Spi::run(
            "DELETE FROM command_fw.audit_log \
             WHERE query_text = 'TRUNCATE t'",
        )
        .unwrap();
    }
}
