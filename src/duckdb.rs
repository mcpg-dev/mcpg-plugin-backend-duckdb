//! Embedded DuckDB machinery: a blocking statement runner, the engine guards
//! (read-only keyword guard + external-access default-deny), a lazy connection
//! pool for file databases, and the row → JSON marshaller.
//!
//! `duckdb` is synchronous (rusqlite-like) and DuckDB is compiled in (the
//! `bundled` C++ engine), so the whole open + init + attach + query runs inside
//! a `spawn_blocking` closure (see `lib.rs`). The marshaller is exercised
//! against a real `:memory:` engine in the unit tests below — no Docker / no
//! external service.
//!
//! `duckdb::Connection` is `Send` (but `!Sync`, rusqlite-style), so **file**
//! databases reuse connections through a lazy `deadpool` pool: the
//! [`DuckDbManager`] opens a guarded connection (read-only / external-access
//! flags applied at open, then `init_sql` + ATTACH run once per pooled
//! connection), and the pooled [`Object`] is moved into the per-call
//! `spawn_blocking`. A `:memory:` database is **never** pooled — each call opens
//! a fresh, empty ephemeral engine that `init_sql` re-seeds, so `:memory:`
//! stays per-call ephemeral; persistent data needs a file database.

use base64::Engine as _;
use deadpool::managed::{Manager, Metrics, Pool, RecycleError, RecycleResult};
use duckdb::types::{Value as DuckValue, ValueRef};
use duckdb::{AccessMode, Config, Connection, params_from_iter};
use serde_json::{Map, Number, Value};

use crate::params::DuckBind;
use crate::types::DuckDbAttach;

/// Outcome of a completed query: the JSON rows (capped at `max_rows`) plus
/// whether more rows existed beyond the cap.
#[derive(Debug)]
pub struct QueryOutcome {
    pub rows: Vec<Value>,
    pub truncated: bool,
    pub row_count: usize,
}

/// Reject a statement that is not read-only, delegating to the shared hardened
/// guard. Beyond the leading-keyword allowlist (`SELECT`/`WITH`/`SHOW`/
/// `DESCRIBE`/`DESC`/`EXPLAIN`), it also rejects write/DDL keywords anywhere
/// (write-CTEs), `EXPLAIN ANALYZE`, and stacked statements, scanning a skeleton
/// with literals/comments blanked. Fail-closed: an empty statement is rejected.
pub fn enforce_read_only(statement: &str) -> Result<(), String> {
    mcpg_plugin_sdk::sql_guard::enforce_read_only(statement)
}

/// Validate an ATTACH alias against a safe-identifier pattern so the operator-
/// fixed `ATTACH '<source>' AS <alias>` cannot smuggle SQL through the alias.
pub fn valid_attach_alias(alias: &str) -> bool {
    let mut chars = alias.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphabetic() || c == '_' => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Single-quote-escape an ATTACH source for embedding in `ATTACH '...'`. The
/// source is operator-fixed, but escaping the quote keeps a literal apostrophe
/// from breaking the statement.
fn sql_quote(s: &str) -> String {
    s.replace('\'', "''")
}

/// Lower a scalar bind to a DuckDB owned [`DuckValue`]. Bool binds natively;
/// a NULL binds as a typed NULL.
fn bind_value(value: &DuckBind) -> DuckValue {
    match value {
        DuckBind::Null => DuckValue::Null,
        DuckBind::Int(i) => DuckValue::BigInt(*i),
        DuckBind::Float(f) => DuckValue::Double(*f),
        DuckBind::Bool(b) => DuckValue::Boolean(*b),
        DuckBind::Str(s) => DuckValue::Text(s.clone()),
    }
}

/// Open a connection with the engine guards applied, then run `init_sql` and
/// the ATTACH statements. Blocking — call from `spawn_blocking`.
///
/// `read_only` opens a *file* database read-only; `:memory:` cannot be opened
/// read-only (there is nothing on disk to protect), so the open-mode flag is
/// skipped for it and the statement read-only guard is the sole defense.
/// `allow_external_access=false` disables DuckDB external access at startup, so
/// `read_csv` / `read_parquet` / `httpfs` / `ATTACH <file>` all fail before
/// touching the filesystem or network.
fn open_connection(
    database: &str,
    read_only: bool,
    allow_external_access: bool,
    init_sql: &[String],
    attach: &[DuckDbAttach],
) -> Result<Connection, String> {
    let is_memory = database == ":memory:";

    let mut config = Config::default()
        .enable_external_access(allow_external_access)
        .map_err(|e| format!("DuckDB config (external access) failed: {e}"))?;
    if read_only && !is_memory {
        config = config
            .access_mode(AccessMode::ReadOnly)
            .map_err(|e| format!("DuckDB config (read-only) failed: {e}"))?;
    }

    let conn = Connection::open_with_flags(database, config).map_err(|e| {
        mcpg_plugin_protocol::redact::redact_in_text(&format!("DuckDB open failed: {e}"))
    })?;

    for (i, sql) in init_sql.iter().enumerate() {
        conn.execute_batch(sql)
            .map_err(|e| format!("DuckDB init_sql[{i}] failed: {e}"))?;
    }

    for a in attach {
        // Alias is validated at register; re-checked here as defense in depth.
        if !valid_attach_alias(&a.alias) {
            return Err(format!(
                "DuckDB attach alias `{}` is not a safe identifier",
                a.alias
            ));
        }
        let mode = if a.read_only { " (READ_ONLY)" } else { "" };
        let stmt = format!("ATTACH '{}' AS {}{}", sql_quote(&a.source), a.alias, mode);
        conn.execute_batch(&stmt)
            .map_err(|e| format!("DuckDB attach `{}` failed: {e}", a.alias))?;
    }

    Ok(conn)
}

/// Resolved catalog-introspection filters for one call. Each is an optional
/// string; `None` means "no filter on this column". Built by resolving the
/// operator-static value against the (optional) per-call argument.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct CatalogFilters {
    pub catalog: Option<String>,
    pub schema: Option<String>,
    pub table: Option<String>,
    pub table_type: Option<String>,
}

/// Build the `list_tables` introspection query over `information_schema.tables`.
/// Every resolved filter is appended as a BOUND `?` parameter — never
/// interpolated — so caller-supplied filter values can only narrow the result,
/// never alter the query. Returns the SQL plus the binds in placeholder order.
#[must_use]
pub fn build_list_tables_sql(filters: &CatalogFilters) -> (String, Vec<DuckBind>) {
    let mut sql = String::from(
        "SELECT table_catalog, table_schema, table_name, table_type \
         FROM information_schema.tables",
    );
    let mut binds = Vec::new();
    let mut wheres = Vec::new();
    push_eq_filter(&mut wheres, &mut binds, "table_catalog", &filters.catalog);
    push_eq_filter(&mut wheres, &mut binds, "table_schema", &filters.schema);
    push_eq_filter(&mut wheres, &mut binds, "table_name", &filters.table);
    push_eq_filter(&mut wheres, &mut binds, "table_type", &filters.table_type);
    if !wheres.is_empty() {
        sql.push_str(" WHERE ");
        sql.push_str(&wheres.join(" AND "));
    }
    sql.push_str(" ORDER BY table_schema, table_name");
    (sql, binds)
}

/// Build the `list_columns` introspection query over
/// `information_schema.columns`. Filters bind as `?` params (never
/// interpolated). The `table` filter scopes the listing to one table.
#[must_use]
pub fn build_list_columns_sql(filters: &CatalogFilters) -> (String, Vec<DuckBind>) {
    let mut sql = String::from(
        "SELECT table_name, column_name, data_type, is_nullable, ordinal_position \
         FROM information_schema.columns",
    );
    let mut binds = Vec::new();
    let mut wheres = Vec::new();
    push_eq_filter(&mut wheres, &mut binds, "table_catalog", &filters.catalog);
    push_eq_filter(&mut wheres, &mut binds, "table_schema", &filters.schema);
    push_eq_filter(&mut wheres, &mut binds, "table_name", &filters.table);
    if !wheres.is_empty() {
        sql.push_str(" WHERE ");
        sql.push_str(&wheres.join(" AND "));
    }
    sql.push_str(" ORDER BY table_name, ordinal_position");
    (sql, binds)
}

/// Append a `col = ?` clause and its bind when the filter is present and
/// non-empty. The column name is a compile-time literal (never caller input);
/// the value is always BOUND, never interpolated.
fn push_eq_filter(
    wheres: &mut Vec<String>,
    binds: &mut Vec<DuckBind>,
    column: &str,
    value: &Option<String>,
) {
    if let Some(v) = value
        && !v.is_empty()
    {
        wheres.push(format!("{column} = ?"));
        binds.push(DuckBind::Str(v.clone()));
    }
}

/// Build the `read_file` query over an OPERATOR-CONFIGURED Parquet / CSV path.
///
/// SAFETY: `path` and `table_function` are operator-fixed (validated at
/// register) — they are never caller input, so a caller cannot redirect the read
/// at an arbitrary file. The path is single-quote-escaped and embedded in the
/// table-function call (DuckDB's `read_parquet` / `read_csv_auto` take the path
/// as a string literal, not a bindable parameter, in this scalar form). The
/// only caller-derived values are the `?` binds in the operator-fixed
/// `predicate`, which cross as bound parameters (injection-safe). The projection
/// columns are validated safe identifiers at register.
#[must_use]
pub fn build_read_file_sql(
    table_function: &str,
    path: &str,
    columns: &[String],
    predicate: Option<&str>,
) -> String {
    let projection = if columns.is_empty() {
        "*".to_owned()
    } else {
        columns.join(", ")
    };
    let mut sql = format!(
        "SELECT {projection} FROM {table_function}('{}')",
        sql_quote(path)
    );
    if let Some(pred) = predicate
        && !pred.trim().is_empty()
    {
        sql.push_str(" WHERE ");
        sql.push_str(pred);
    }
    sql
}

/// deadpool manager for a **file** DuckDB database. `create` opens a guarded
/// connection (read-only / external-access flags applied at open, then
/// `init_sql` + ATTACH run once on this pooled connection) on a blocking thread;
/// `recycle` runs a cheap `SELECT 1` to confirm the handle is still usable.
/// Never used for `:memory:` (the gateway path opens those per call).
pub struct DuckDbManager {
    database: String,
    read_only: bool,
    allow_external_access: bool,
    init_sql: Vec<String>,
    attach: Vec<DuckDbAttach>,
}

impl DuckDbManager {
    #[must_use]
    pub fn new(
        database: String,
        read_only: bool,
        allow_external_access: bool,
        init_sql: Vec<String>,
        attach: Vec<DuckDbAttach>,
    ) -> Self {
        Self {
            database,
            read_only,
            allow_external_access,
            init_sql,
            attach,
        }
    }
}

impl Manager for DuckDbManager {
    type Type = Connection;
    type Error = String;

    async fn create(&self) -> Result<Connection, String> {
        let database = self.database.clone();
        let read_only = self.read_only;
        let allow_external_access = self.allow_external_access;
        let init_sql = self.init_sql.clone();
        let attach = self.attach.clone();
        // The open + init_sql + ATTACH are blocking C++ calls; run them off the
        // async runtime. This runs ONCE per pooled connection, not per call —
        // `init_sql` (INSTALL / LOAD / CREATE SECRET) and ATTACH are idempotent
        // setup applied at open time, and the guards (read_only open-mode,
        // external-access default-deny) are applied here so every pooled
        // connection inherits them.
        tokio::task::spawn_blocking(move || {
            open_connection(
                &database,
                read_only,
                allow_external_access,
                &init_sql,
                &attach,
            )
        })
        .await
        .map_err(|e| format!("DuckDB open worker task failed: {e}"))?
    }

    async fn recycle(&self, conn: &mut Connection, _m: &Metrics) -> RecycleResult<String> {
        // Cheap liveness check before reuse. DuckDB is synchronous and this
        // takes only a `&self` borrow; `spawn_blocking` needs a `'static` value
        // and the pool only lends `&mut Connection`, so this trivial in-process
        // query runs inline (it is not a per-call statement). A failure evicts
        // the connection and the pool opens a fresh one.
        conn.execute_batch("SELECT 1")
            .map_err(|e| RecycleError::Backend(format!("recycle ping failed: {e}")))
    }
}

/// Pool alias for one file-database binding.
pub type DuckDbPool = Pool<DuckDbManager>;

/// Build a per-binding connection pool for a file database. This is LAZY — no
/// connection is opened until the first `pool.get()`, so it is safe to call
/// from `register_profile` without touching the filesystem.
pub fn build_pool(manager: DuckDbManager, max_size: usize) -> Result<DuckDbPool, String> {
    Pool::builder(manager)
        .max_size(max_size)
        .build()
        .map_err(|e| format!("DuckDB pool build failed: {e}"))
}

/// Open a fresh connection (with the engine guards + init_sql + attach), then
/// prepare, bind, and run the query, marshalling rows to capped JSON. Blocking —
/// call from `spawn_blocking`. Used for `:memory:` databases, which are opened
/// per call (each call gets a fresh ephemeral engine that `init_sql` re-seeds).
#[allow(clippy::too_many_arguments)]
pub fn run_query_blocking(
    database: &str,
    read_only: bool,
    allow_external_access: bool,
    init_sql: &[String],
    attach: &[DuckDbAttach],
    statement: &str,
    bound: Vec<DuckBind>,
    max_rows: usize,
) -> Result<QueryOutcome, String> {
    let conn = open_connection(database, read_only, allow_external_access, init_sql, attach)?;
    run_query_on_conn(&conn, statement, bound, max_rows)
}

/// Prepare, bind, and run the query on an already-open connection, marshalling
/// rows to capped JSON. Blocking — call from `spawn_blocking`. Used for the
/// pooled file-database path (the connection is drawn from [`DuckDbPool`] and
/// already carries the guards + init_sql + ATTACH applied at open).
pub fn run_query_on_conn(
    conn: &Connection,
    statement: &str,
    bound: Vec<DuckBind>,
    max_rows: usize,
) -> Result<QueryOutcome, String> {
    let mut stmt = conn
        .prepare(statement)
        .map_err(|e| format!("DuckDB prepare failed: {e}"))?;

    let values: Vec<DuckValue> = bound.iter().map(bind_value).collect();
    let mut rows = stmt
        .query(params_from_iter(values))
        .map_err(|e| format!("DuckDB query failed: {e}"))?;

    // Column names are stable for the whole result set; capture them up front so
    // the immutable borrow they take does not collide with `rows.next()` below.
    // After `query()` the statement has been executed, so `column_names()` is
    // safe to call (it panics only before execution).
    let columns: Vec<String> = rows.as_ref().map(|s| s.column_names()).unwrap_or_default();

    let mut out = Vec::new();
    let mut truncated = false;
    let mut row_count = 0usize;
    while let Some(row) = rows
        .next()
        .map_err(|e| format!("DuckDB row read failed: {e}"))?
    {
        row_count += 1;
        if out.len() >= max_rows {
            truncated = true;
            // Drain the remaining rows so the count is exact without retaining
            // them. The cap is on materialised rows, not on the scan.
            continue;
        }
        out.push(row_to_json(row, &columns));
    }

    Ok(QueryOutcome {
        rows: out,
        truncated,
        row_count,
    })
}

/// One row → `{ column: value, … }`, projected by the column's runtime
/// [`ValueRef`]. Column names stay as the query reports them; duplicate names
/// collapse (last wins) — alias them in the query. Never panics: any unknown /
/// unconvertible value falls back to a string.
fn row_to_json(row: &duckdb::Row<'_>, columns: &[String]) -> Value {
    let mut obj = Map::with_capacity(columns.len());
    for (i, name) in columns.iter().enumerate() {
        let v = match row.get_ref(i) {
            Ok(vr) => value_ref_to_json(vr),
            Err(_) => Value::Null,
        };
        obj.insert(name.clone(), v);
    }
    Value::Object(obj)
}

/// Project one [`ValueRef`] to JSON. Integers that overflow `i64` (HugeInt,
/// large UBigInt) and decimals are emitted as strings to preserve fidelity;
/// blobs are base64; temporal / interval / list / struct / map / array / enum /
/// union types are stringified.
fn value_ref_to_json(v: ValueRef<'_>) -> Value {
    match v {
        ValueRef::Null => Value::Null,
        ValueRef::Boolean(b) => Value::Bool(b),
        ValueRef::TinyInt(i) => Value::Number(i64::from(i).into()),
        ValueRef::SmallInt(i) => Value::Number(i64::from(i).into()),
        ValueRef::Int(i) => Value::Number(i64::from(i).into()),
        ValueRef::BigInt(i) => Value::Number(i.into()),
        ValueRef::UTinyInt(i) => Value::Number(i64::from(i).into()),
        ValueRef::USmallInt(i) => Value::Number(i64::from(i).into()),
        ValueRef::UInt(i) => Value::Number(i64::from(i).into()),
        ValueRef::UBigInt(i) => match i64::try_from(i) {
            Ok(n) => Value::Number(n.into()),
            Err(_) => Value::String(i.to_string()),
        },
        ValueRef::HugeInt(i) => match i64::try_from(i) {
            Ok(n) => Value::Number(n.into()),
            Err(_) => Value::String(i.to_string()),
        },
        ValueRef::Float(f) => f64_to_json(f64::from(f)),
        ValueRef::Double(f) => f64_to_json(f),
        // Keep full precision — JSON has no decimal type.
        ValueRef::Decimal(d) => Value::String(d.to_string()),
        ValueRef::Text(bytes) => Value::String(String::from_utf8_lossy(bytes).into_owned()),
        ValueRef::Blob(bytes) => {
            Value::String(base64::engine::general_purpose::STANDARD.encode(bytes))
        }
        // Temporal / interval types: stringify the raw representation.
        ValueRef::Timestamp(unit, n) => Value::String(format!("{n} {unit:?}")),
        ValueRef::Date32(d) => Value::String(d.to_string()),
        ValueRef::Time64(unit, n) => Value::String(format!("{n} {unit:?}")),
        ValueRef::Interval {
            months,
            days,
            nanos,
        } => Value::String(format!("{months}mo {days}d {nanos}ns")),
        // Composite / dictionary / other types: a Debug stringification keeps
        // the marshaller total without pulling in arrow row decoding.
        other => Value::String(format!("{other:?}")),
    }
}

fn f64_to_json(f: f64) -> Value {
    Number::from_f64(f)
        .map(Value::Number)
        .unwrap_or(Value::Null)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn outcome(
        statement: &str,
        allow_external: bool,
        binds: Vec<DuckBind>,
    ) -> Result<QueryOutcome, String> {
        run_query_blocking(
            ":memory:",
            false,
            allow_external,
            &[],
            &[],
            statement,
            binds,
            1_000,
        )
    }

    #[test]
    fn read_only_guard_allows_reads() {
        for s in [
            "SELECT 1",
            "  with x as (select 1) select * from x",
            "-- comment\nSELECT 2",
            "/* hi */ EXPLAIN SELECT 1",
            "SHOW TABLES",
            "DESCRIBE SELECT 1",
        ] {
            assert!(enforce_read_only(s).is_ok(), "should allow: {s}");
        }
    }

    #[test]
    fn read_only_guard_rejects_writes_and_ddl() {
        for s in [
            "INSERT INTO t VALUES (1)",
            "UPDATE t SET x = 1",
            "DELETE FROM t",
            "CREATE TABLE t(x int)",
            "DROP TABLE t",
            "ATTACH 'x.db' AS y",
            "   ",
            "",
        ] {
            assert!(enforce_read_only(s).is_err(), "should reject: {s}");
        }
    }

    #[test]
    fn read_only_guard_delegates_to_hardened_shared_guard() {
        // The shared guard catches constructs the old leading-keyword-only
        // check missed: write-CTEs, EXPLAIN ANALYZE, and stacked statements.
        assert!(enforce_read_only("WITH x AS (INSERT INTO t SELECT 1) SELECT * FROM x").is_err());
        assert!(enforce_read_only("EXPLAIN ANALYZE SELECT 1").is_err());
        assert!(enforce_read_only("SELECT 1; DROP TABLE t").is_err());
        assert!(enforce_read_only("SELECT 1").is_ok());
    }

    #[test]
    fn attach_alias_validation() {
        assert!(valid_attach_alias("lake"));
        assert!(valid_attach_alias("_db1"));
        assert!(valid_attach_alias("Catalog_2"));
        assert!(!valid_attach_alias("1lake"));
        assert!(!valid_attach_alias("la ke"));
        assert!(!valid_attach_alias("la);DROP"));
        assert!(!valid_attach_alias(""));
    }

    #[test]
    fn marshals_scalar_columns() {
        let oc = outcome(
            "SELECT 42 AS id, 'alice' AS name, NULL AS x, true AS active",
            false,
            vec![],
        )
        .expect("query");
        assert_eq!(oc.row_count, 1);
        assert!(!oc.truncated);
        assert_eq!(
            oc.rows[0],
            json!({ "id": 42, "name": "alice", "x": null, "active": true })
        );
    }

    #[test]
    fn marshals_float_and_blob_and_bigint() {
        // `1.5` unsuffixed types as DECIMAL (stringified for precision); cast to
        // DOUBLE to exercise the float → JSON number path.
        let oc = outcome(
            "SELECT 1.5::DOUBLE AS f, '\\x00\\x01'::BLOB AS b, 9223372036854775807::BIGINT AS big",
            false,
            vec![],
        )
        .expect("query");
        assert_eq!(oc.rows[0]["f"], json!(1.5));
        assert_eq!(oc.rows[0]["big"], json!(9_223_372_036_854_775_807i64));
        // base64 of bytes 0x00 0x01
        assert_eq!(oc.rows[0]["b"], json!("AAE="));
    }

    #[test]
    fn hugeint_overflowing_i64_is_stringified() {
        let oc = outcome(
            "SELECT 170141183460469231731687303715884105727::HUGEINT AS h",
            false,
            vec![],
        )
        .expect("query");
        assert_eq!(
            oc.rows[0]["h"],
            json!("170141183460469231731687303715884105727")
        );
    }

    #[test]
    fn bound_parameter_round_trips() {
        // Build a table, then read it back filtered by a bound parameter.
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch("CREATE TABLE people(id INTEGER, name TEXT); INSERT INTO people VALUES (1,'alice'),(2,'bob')")
            .unwrap();
        // Run the parameterised SELECT through the same marshalling path used in
        // production by preparing + querying on this connection.
        let mut stmt = conn
            .prepare("SELECT id, name FROM people WHERE id = ?")
            .unwrap();
        let values = vec![bind_value(&DuckBind::Int(2))];
        let mut rows = stmt.query(params_from_iter(values)).unwrap();
        let columns: Vec<String> = rows.as_ref().unwrap().column_names();
        let row = rows.next().unwrap().expect("one row");
        let json = row_to_json(row, &columns);
        assert_eq!(json, json!({ "id": 2, "name": "bob" }));
        assert!(rows.next().unwrap().is_none());
    }

    #[test]
    fn max_rows_cap_sets_truncated_and_exact_count() {
        let oc = run_query_blocking(
            ":memory:",
            false,
            false,
            &[],
            &[],
            "SELECT * FROM range(10) AS t(n)",
            vec![],
            3,
        )
        .expect("query");
        assert_eq!(oc.rows.len(), 3);
        assert!(oc.truncated);
        assert_eq!(oc.row_count, 10);
    }

    #[test]
    fn list_tables_sql_binds_filters_as_params() {
        let filters = CatalogFilters {
            schema: Some("main".into()),
            table_type: Some("VIEW".into()),
            ..Default::default()
        };
        let (sql, binds) = build_list_tables_sql(&filters);
        assert!(sql.contains("information_schema.tables"));
        // Filters appear as `col = ?`, NEVER the literal value.
        assert!(sql.contains("table_schema = ?"));
        assert!(sql.contains("table_type = ?"));
        assert!(
            !sql.contains("main"),
            "value must be bound, not interpolated"
        );
        assert!(
            !sql.contains("VIEW"),
            "value must be bound, not interpolated"
        );
        assert_eq!(
            binds,
            vec![DuckBind::Str("main".into()), DuckBind::Str("VIEW".into())]
        );
    }

    #[test]
    fn list_tables_sql_no_filters_has_no_where() {
        let (sql, binds) = build_list_tables_sql(&CatalogFilters::default());
        assert!(!sql.contains("WHERE"));
        assert!(binds.is_empty());
    }

    #[test]
    fn list_columns_sql_binds_table_filter() {
        let filters = CatalogFilters {
            table: Some("customers".into()),
            ..Default::default()
        };
        let (sql, binds) = build_list_columns_sql(&filters);
        assert!(sql.contains("information_schema.columns"));
        assert!(sql.contains("table_name = ?"));
        assert!(sql.contains("ordinal_position"));
        assert!(!sql.contains("customers"), "value must be bound");
        assert_eq!(binds, vec![DuckBind::Str("customers".into())]);
    }

    #[test]
    fn list_tables_runs_against_real_engine() {
        // Create two tables in a fresh engine, then introspect them.
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch("CREATE TABLE a(x INTEGER); CREATE TABLE b(y TEXT)")
            .unwrap();
        let (sql, binds) = build_list_tables_sql(&CatalogFilters {
            schema: Some("main".into()),
            ..Default::default()
        });
        let oc = run_query_on_conn(&conn, &sql, binds, 100).expect("introspect");
        assert_eq!(oc.row_count, 2);
        let names: Vec<&str> = oc
            .rows
            .iter()
            .filter_map(|r| r["table_name"].as_str())
            .collect();
        assert!(names.contains(&"a") && names.contains(&"b"));
    }

    #[test]
    fn list_columns_runs_against_real_engine() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch("CREATE TABLE people(id INTEGER, name TEXT)")
            .unwrap();
        let (sql, binds) = build_list_columns_sql(&CatalogFilters {
            table: Some("people".into()),
            ..Default::default()
        });
        let oc = run_query_on_conn(&conn, &sql, binds, 100).expect("introspect");
        assert_eq!(oc.row_count, 2);
        assert_eq!(oc.rows[0]["column_name"], json!("id"));
        assert_eq!(oc.rows[0]["ordinal_position"], json!(1));
        assert_eq!(oc.rows[1]["column_name"], json!("name"));
    }

    #[test]
    fn read_file_sql_escapes_path_and_binds_predicate() {
        let sql = build_read_file_sql(
            "read_parquet",
            "/data/o'brien/*.parquet",
            &["region".to_owned(), "amount".to_owned()],
            Some("amount > ?"),
        );
        assert_eq!(
            sql,
            "SELECT region, amount FROM read_parquet('/data/o''brien/*.parquet') WHERE amount > ?"
        );
    }

    #[test]
    fn read_file_sql_defaults_to_star_and_no_where() {
        let sql = build_read_file_sql("read_csv_auto", "/data/x.csv", &[], None);
        assert_eq!(sql, "SELECT * FROM read_csv_auto('/data/x.csv')");
    }

    #[test]
    fn read_file_reads_real_csv_with_external_access() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("data.csv");
        std::fs::write(&path, "region,amount\nemea,100\napac,5\n").unwrap();
        let sql = build_read_file_sql(
            "read_csv_auto",
            &path.display().to_string(),
            &[],
            Some("amount > ?"),
        );
        // external access enabled so the engine may touch the file.
        let oc = run_query_blocking(
            ":memory:",
            false,
            true,
            &[],
            &[],
            &sql,
            vec![DuckBind::Int(50)],
            100,
        )
        .expect("read_file");
        assert_eq!(oc.row_count, 1);
        assert_eq!(oc.rows[0]["region"], json!("emea"));
        assert_eq!(oc.rows[0]["amount"], json!(100));
    }

    #[test]
    fn external_access_denied_rejects_read_csv() {
        // Write a real CSV, then prove that with allow_external_access=false the
        // engine refuses to read it (does not exfiltrate the file).
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secret.csv");
        std::fs::write(&path, "a,b\n1,2\n").unwrap();
        let stmt = format!("SELECT * FROM read_csv_auto('{}')", path.display());

        let denied = outcome(&stmt, false, vec![]);
        assert!(
            denied.is_err(),
            "read_csv must be rejected when external access is disabled, got: {denied:?}"
        );

        // With external access enabled the same read succeeds.
        let allowed = outcome(&stmt, true, vec![]).expect("read_csv with external access");
        assert_eq!(allowed.row_count, 1);
        assert_eq!(allowed.rows[0]["a"], json!(1));
        assert_eq!(allowed.rows[0]["b"], json!(2));
    }
}
