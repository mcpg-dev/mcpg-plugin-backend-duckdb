//! Operator-facing spec for the DuckDB backend plugin.
//!
//! One binding = one operator-fixed analytical statement = one MCP tool (or
//! resource). The database (a file path or `:memory:`), the engine guards
//! (`read_only` / `allow_external_access`), the operator init SQL + ATTACH
//! targets, the statement and the query bounds all live on the per-binding
//! spec, mirroring the oracle/snowflake/mssql one-profile-per-binding shape.

use serde::Deserialize;

/// One operator ATTACH target. `ATTACH '<source>' AS <alias> (READ_ONLY)` is
/// built at open. The `alias` is validated against a safe-identifier pattern at
/// registration (no SQL-injection via the alias); `source` is operator-fixed.
#[derive(Debug, Clone, Deserialize)]
pub struct DuckDbAttach {
    /// Catalog alias the attached database is referenced by. Must match
    /// `[A-Za-z_][A-Za-z0-9_]*` (validated at register).
    pub alias: String,
    /// The database to attach — a file path or a connection string. Operator-
    /// fixed (never caller-templated).
    pub source: String,
    /// Attach the catalog read-only.
    #[serde(default)]
    pub read_only: bool,
}

/// The operation a binding performs.
///
/// `query` (default) runs the operator-fixed `statement`. `list_tables` /
/// `list_columns` are read-only schema-discovery introspection over the
/// engine's `information_schema` views (no caller SQL). `read_file` exposes
/// DuckDB's external-file table functions (`read_parquet` / `read_csv_auto`)
/// over an OPERATOR-CONFIGURED path/glob — the path is never a caller argument.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DuckDbOperation {
    /// Run the operator-fixed `statement` with `?` binds (the default).
    #[default]
    Query,
    /// Discover tables/views via `information_schema.tables`.
    ListTables,
    /// Discover a table's columns via `information_schema.columns`.
    ListColumns,
    /// Read rows from an operator-configured external Parquet / CSV file or
    /// glob via DuckDB's `read_parquet` / `read_csv_auto` table functions.
    ReadFile,
}

impl DuckDbOperation {
    /// Lowercase wire token (matches the `serde` rename).
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            DuckDbOperation::Query => "query",
            DuckDbOperation::ListTables => "list_tables",
            DuckDbOperation::ListColumns => "list_columns",
            DuckDbOperation::ReadFile => "read_file",
        }
    }

    /// Whether this is a catalog-introspection operation (inherently read-only,
    /// driven by `information_schema`, not by the `statement`).
    #[must_use]
    pub fn is_catalog(self) -> bool {
        matches!(
            self,
            DuckDbOperation::ListTables | DuckDbOperation::ListColumns
        )
    }
}

/// The external-file format an `operation: read_file` binding reads. Selects the
/// DuckDB table function: `parquet` → `read_parquet`, `csv` → `read_csv_auto`.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReadFileFormat {
    /// `read_parquet('<path>')` (the default).
    #[default]
    Parquet,
    /// `read_csv_auto('<path>')` — schema-sniffed CSV.
    Csv,
}

impl ReadFileFormat {
    /// The DuckDB table function name for this format.
    #[must_use]
    pub fn table_function(self) -> &'static str {
        match self {
            ReadFileFormat::Parquet => "read_parquet",
            ReadFileFormat::Csv => "read_csv_auto",
        }
    }
}

/// Operator-fixed external-file read config for `operation: read_file`.
///
/// SAFETY: `path` is OPERATOR-CONFIG ONLY — it is fixed in the binding spec and
/// is NEVER taken from a caller argument. A caller-supplied path/glob would be
/// an arbitrary-file-read (LFI / SSRF over `httpfs`) vector, so the binding
/// exposes no path argument at all. The only caller-derived inputs are the
/// optional `?` binds in `predicate` (bound, never interpolated).
#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct ReadFileConfig {
    /// The operator-fixed file path or glob (e.g. `/data/sales/*.parquet`,
    /// `s3://bucket/events/*.csv`). Fixed in config; never caller-templated.
    pub path: String,
    /// File format — `parquet` (default) or `csv`.
    #[serde(default)]
    pub format: ReadFileFormat,
    /// Optional projection: the column list for the SELECT. Each must be a safe
    /// SQL identifier (validated at register); empty → `SELECT *`.
    #[serde(default)]
    pub columns: Vec<String>,
    /// Optional operator-fixed `WHERE` predicate. May reference `?` placeholders
    /// bound from `params` (caller args reach it only as bound values — never
    /// interpolated). Empty → no filter.
    #[serde(default)]
    pub predicate: Option<String>,
}

/// Catalog-introspection filters for `operation: list_tables` / `list_columns`.
/// Each is an operator-pinned static value plus an optional tool-argument name;
/// the per-call argument (when configured AND present as a string) overrides the
/// static value. Every resolved filter is BOUND as a `?` parameter in the
/// `information_schema` query — never interpolated — so caller input can only
/// narrow the metadata, never alter the query.
#[derive(Debug, Default, Clone, Deserialize, PartialEq)]
pub struct CatalogFilterConfig {
    /// Static `table_catalog` filter.
    #[serde(default)]
    pub catalog: Option<String>,
    /// Static `table_schema` filter.
    #[serde(default)]
    pub schema: Option<String>,
    /// Static `table_name` filter. For `list_columns` this is the table whose
    /// columns are listed.
    #[serde(default)]
    pub table: Option<String>,
    /// Static `table_type` filter for `list_tables` (e.g. `BASE TABLE`, `VIEW`).
    /// Ignored by `list_columns`.
    #[serde(default)]
    pub table_type: Option<String>,
    /// Tool-argument name supplying the catalog filter at call time.
    #[serde(default)]
    pub catalog_arg: Option<String>,
    /// Tool-argument name supplying the schema filter at call time.
    #[serde(default)]
    pub schema_arg: Option<String>,
    /// Tool-argument name supplying the table filter at call time.
    #[serde(default)]
    pub table_arg: Option<String>,
    /// Tool-argument name supplying the table-type filter at call time
    /// (`list_tables`).
    #[serde(default)]
    pub table_type_arg: Option<String>,
}

impl CatalogFilterConfig {
    /// The distinct tool-argument names this config reads from call arguments,
    /// in filter order — surfaced as the catalog op's `input_schema` properties.
    #[must_use]
    pub fn argument_names(&self) -> Vec<String> {
        let mut names = Vec::new();
        for arg in [
            &self.catalog_arg,
            &self.schema_arg,
            &self.table_arg,
            &self.table_type_arg,
        ]
        .into_iter()
        .flatten()
        {
            if !names.contains(arg) {
                names.push(arg.clone());
            }
        }
        names
    }
}

/// Query-execution bounds.
#[derive(Debug, Clone, Deserialize)]
pub struct DuckDbQueryConfig {
    /// Per-call ceiling (ms) on the whole open + statement + read (default
    /// 30 s). Enforced as the outer tokio timeout around the blocking task.
    #[serde(default = "default_statement_timeout_ms")]
    pub statement_timeout_ms: u64,

    /// Client-side cap on returned rows (default 100000). Extra rows set the
    /// envelope `truncated` flag.
    #[serde(default = "default_max_rows")]
    pub max_rows: usize,
}

impl Default for DuckDbQueryConfig {
    fn default() -> Self {
        Self {
            statement_timeout_ms: default_statement_timeout_ms(),
            max_rows: default_max_rows(),
        }
    }
}

fn default_statement_timeout_ms() -> u64 {
    30_000
}
fn default_max_rows() -> usize {
    100_000
}
fn default_read_only() -> bool {
    true
}
fn default_pool_max_size() -> usize {
    2
}

/// Operator-facing spec the gateway serializes when calling `register_profile`.
/// Mirrors `DuckDbBackendConfig` in the gateway crate.
// NOTE: intentionally NOT #[serde(deny_unknown_fields)] — the gateway injects
// the reserved `__mcpg_secret_refs` hint key into this spec at register_profile
// (secret-rotation scoping); denying unknown fields would reject it. The
// operator-facing schema is closed on the gateway-side *BackendConfig instead.
#[derive(Debug, Clone, Deserialize)]
pub struct DuckDbBackendSpec {
    /// The database: `:memory:` for an ephemeral in-process engine, or a file
    /// path for a persistent one. Operator-configured (never caller-templated),
    /// so there is no path-injection / SSRF vector on the database itself.
    /// `:memory:` is opened per call, so it is ephemeral — for data that must
    /// survive across calls, use a file path (see README).
    pub database: String,

    /// The single canonical read-only switch. When true (default) it both
    /// (a) opens the engine itself read-only (file DBs; `:memory:` can't be
    /// opened read-only, so it relies on the guard alone) AND (b) rejects the
    /// `statement` at register unless it starts with a read-only keyword
    /// (SELECT / WITH / SHOW / DESCRIBE / EXPLAIN). One field, two defenses.
    #[serde(default = "default_read_only")]
    pub read_only: bool,

    /// Allow the engine to touch the filesystem / network beyond the database
    /// file (`read_csv` / `read_parquet` / `httpfs` / `ATTACH <file>`). Default
    /// FALSE — DuckDB external access is disabled, so even the operator-fixed
    /// statement cannot read arbitrary files or reach the network. Set true to
    /// opt into lake / S3 analytics (and to make `attach`/`init_sql` that touch
    /// external sources work).
    #[serde(default)]
    pub allow_external_access: bool,

    /// Operator SQL run once when the connection is opened (before the
    /// statement), e.g. `INSTALL httpfs; LOAD httpfs;`, `CREATE SECRET ...`.
    /// These may already carry `${cred://...}` / `${env.X}` values the gateway
    /// secret-resolver expanded at config load.
    #[serde(default)]
    pub init_sql: Vec<String>,

    /// Operator ATTACH targets, applied after `init_sql`.
    #[serde(default)]
    pub attach: Vec<DuckDbAttach>,

    /// Which operation this binding performs. `query` (default) runs the
    /// operator-fixed `statement`; `list_tables` / `list_columns` run read-only
    /// `information_schema` introspection; `read_file` reads an operator-fixed
    /// external Parquet / CSV path via DuckDB's table functions. The catalog and
    /// `read_file` operations ignore `statement`.
    #[serde(default)]
    pub operation: DuckDbOperation,

    /// The operator-fixed statement for `operation: query`. Uses `?` positional
    /// bind placeholders bound from `params`. The statement text is operator-
    /// fixed — it is NOT templated from caller arguments. Required for
    /// `operation: query`; ignored (and may be omitted) for the catalog /
    /// `read_file` operations.
    #[serde(default)]
    pub statement: String,

    /// Catalog-introspection filters for `operation: list_tables` /
    /// `list_columns`. Each filter is BOUND as a `?` parameter in the
    /// `information_schema` query (never interpolated). Ignored by other ops.
    #[serde(default)]
    pub catalog_filters: CatalogFilterConfig,

    /// External-file read config for `operation: read_file`. The `path` is
    /// OPERATOR-CONFIG ONLY (never a caller argument). Required for
    /// `operation: read_file`; ignored by other ops.
    #[serde(default)]
    pub read_file: Option<ReadFileConfig>,

    /// Ordered CEL expressions; `params[i]` → the i-th `?`. Each is evaluated
    /// against the call arguments (`arguments.*`) and bound as a SQL
    /// parameter — injection-safe.
    #[serde(default)]
    pub params: Vec<String>,

    /// Query-execution bounds (timeout, max rows). A bare `query:` or an
    /// omitted block applies all defaults.
    #[serde(default)]
    pub query: DuckDbQueryConfig,

    /// Maximum pooled connections for a **file** database (default 2). DuckDB is
    /// single-writer, so this is a small read pool; for `read_only` file DBs
    /// several handles are fine. Ignored for `:memory:`, which is never pooled
    /// (each call gets a fresh ephemeral engine — see README).
    #[serde(default = "default_pool_max_size")]
    pub pool_max_size: usize,

    /// MCP surface this binding serves. `tool` (default) emits the unchanged
    /// tool envelope; `resource` reshapes successful rows into the
    /// `resources/read` `{contents:[…]}` body; `prompt` reshapes them into the
    /// `prompts/get` `{messages:[…]}` body. Set to match the capability list the
    /// binding is placed under (`resources[]` / `prompts[]`).
    #[serde(default)]
    pub surface: crate::surface::Surface,

    /// Optional static resource URI for `surface: resource`. When set it is used
    /// verbatim as the emitted content `uri`; when omitted the binding uses the
    /// requested URI the gateway passes in the call arguments (`uri`). Ignored
    /// for `tool` / `prompt` surfaces.
    #[serde(default)]
    pub uri: Option<String>,

    /// Optional listing statement for `resources/list`. On a
    /// `surface: resource` binding this runs at list time to enumerate concrete
    /// resource URIs. Operator-fixed; the only caller-derived inputs are the
    /// paginated `?cursor` / `?page_size` binds. Empty → the binding returns no
    /// dynamic listing (the trait default).
    #[serde(default)]
    pub list_query: Option<ListQueryConfig>,

    /// Optional per-`{id}` single-row read statement for a `resource_templates[]`
    /// binding (`surface: resource` with a `uri_template` like
    /// `duckdb://orders/{id}`). On a `resources/read` of a concrete URI the
    /// gateway extracts the template variables and supplies them in the call
    /// arguments (each `{var}` as `arguments.<var>`); this statement's `?`
    /// placeholders are bound from the binding's `params` CEL expressions
    /// (`arguments.<var>`), so the extracted value binds SERVER-SIDE as a query
    /// parameter — never interpolated into SQL (injection-safe). Applies only to
    /// the default `operation: query` resource-read path; when omitted that path
    /// falls back to `statement`. Operator-fixed; required to be read-only under
    /// the read-only guard.
    #[serde(default)]
    pub read_query: Option<String>,

    /// Optional per-template-variable completion config for
    /// `completion/complete`. Keyed by the URI template variable name; each
    /// entry is an operator-fixed query whose single `?` is bound to the
    /// caller-typed prefix (never interpolated — injection-safe). Empty → no
    /// completion candidates (the trait default).
    #[serde(default)]
    pub variable_completions: std::collections::BTreeMap<String, CompletionConfig>,
}

/// Pagination strategy for [`ListQueryConfig`].
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ListQueryMode {
    /// `WHERE cursor_column > ? ORDER BY cursor_column LIMIT ?`. The first `?`
    /// is the keyset cursor (NULL on the first page); the second is page_size.
    #[default]
    Keyset,
    /// `LIMIT ? OFFSET ?` — the first `?` is page_size, the second the offset.
    /// O(offset) on the engine; use only for small, bounded listings.
    Offset,
}

/// Operator-fixed listing statement + pagination shape for `resources/list`.
#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct ListQueryConfig {
    /// SELECT that returns one row per enumerable resource. Required column:
    /// `uri`. Optional columns: `name`, `description`, `mime_type`. The
    /// statement is operator-fixed; the pagination binds (`?cursor` /
    /// `?page_size`) are the only non-operator values.
    pub sql: String,
    /// Pagination mode — `keyset` (default) or `offset`.
    #[serde(default)]
    pub mode: ListQueryMode,
    /// Column the keyset cursor tracks (typically `id` or `updated_at`).
    /// Required for `mode: keyset`; ignored for `mode: offset`.
    #[serde(default)]
    pub cursor_column: Option<String>,
    /// Rows per page (1..=1000). Defaults to 100.
    #[serde(default = "default_list_page_size")]
    pub page_size: u64,
}

/// Operator-fixed completion query for one template variable.
#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct CompletionConfig {
    /// SQL returning candidate values in its first column. MUST reference a
    /// single `?` placeholder — bound to the caller-typed prefix at call time
    /// (e.g. `SELECT name FROM repos WHERE name LIKE ? || '%' LIMIT 100`).
    pub sql: String,
    /// Optional cap on returned candidates; defaults to 100.
    #[serde(default)]
    pub max_results: Option<u32>,
}

fn default_list_page_size() -> u64 {
    100
}

/// Read-only / safe-identifier validation for an operator-fixed
/// [`ListQueryConfig`]. Fail-closed at register so misconfig never reaches a
/// `resources/list` call.
pub fn validate_list_query(cfg: &ListQueryConfig) -> Result<(), String> {
    if cfg.sql.trim().is_empty() {
        return Err("list_query.sql must not be empty".into());
    }
    if cfg.page_size == 0 || cfg.page_size > 1_000 {
        return Err(format!(
            "list_query.page_size ({}) must be in 1..=1000",
            cfg.page_size
        ));
    }
    if cfg.mode == ListQueryMode::Keyset {
        let col = cfg.cursor_column.as_deref().unwrap_or("").trim();
        if col.is_empty() {
            return Err("list_query.cursor_column is required for mode: keyset".into());
        }
        if !is_safe_sql_identifier(col) {
            return Err(format!(
                "list_query.cursor_column '{col}' is not a safe SQL identifier"
            ));
        }
    }
    Ok(())
}

/// Validate an operator-fixed [`CompletionConfig`]: non-empty SQL referencing
/// exactly one `?` placeholder (the bound prefix).
pub fn validate_completion(name: &str, cfg: &CompletionConfig) -> Result<(), String> {
    if cfg.sql.trim().is_empty() {
        return Err(format!("variable_completions.{name}.sql must not be empty"));
    }
    if cfg.sql.matches('?').count() != 1 {
        return Err(format!(
            "variable_completions.{name}.sql must reference exactly one `?` placeholder (bound to the typed prefix)"
        ));
    }
    Ok(())
}

/// Validate an operator-fixed [`ReadFileConfig`] at register. Fail-closed so a
/// misconfigured external-file binding never reaches a call.
///
/// SAFETY NOTE: the `path` is operator-config only — there is no per-call path
/// argument, so a caller can never redirect the read at an arbitrary file. The
/// validation here fences the operator's own config: a non-empty path, safe
/// projection identifiers, and no bare `cred://` (the secret-resolver expands
/// `${cred://…}` at config load; a bare `cred://` would reach DuckDB verbatim).
pub fn validate_read_file(cfg: &ReadFileConfig) -> Result<(), String> {
    if cfg.path.trim().is_empty() {
        return Err("read_file.path must not be empty".into());
    }
    if cfg.path.contains("cred://") {
        return Err(
            "read_file.path must not contain a bare cred:// URI — use ${cred://…} (resolved at config load)".into(),
        );
    }
    for col in &cfg.columns {
        if !is_safe_sql_identifier(col) {
            return Err(format!(
                "read_file.columns entry '{col}' is not a safe SQL identifier"
            ));
        }
    }
    if let Some(pred) = &cfg.predicate
        && pred.trim().is_empty()
    {
        return Err("read_file.predicate must not be empty when set".into());
    }
    Ok(())
}

/// A safe SQL identifier — `[A-Za-z_][A-Za-z0-9_]*`. Used to fence the
/// operator-declared keyset `cursor_column`, which is interpolated into the
/// next-cursor projection.
fn is_safe_sql_identifier(s: &str) -> bool {
    let mut chars = s.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphabetic() || c == '_' => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spec_applies_defaults_when_omitted() {
        let spec: DuckDbBackendSpec = serde_json::from_value(serde_json::json!({
            "database": ":memory:",
            "statement": "SELECT 1 AS one",
        }))
        .unwrap();
        assert!(spec.read_only);
        assert!(!spec.allow_external_access);
        assert_eq!(spec.query.statement_timeout_ms, 30_000);
        assert_eq!(spec.query.max_rows, 100_000);
        assert_eq!(spec.pool_max_size, 2);
        assert!(spec.init_sql.is_empty());
        assert!(spec.attach.is_empty());
        assert!(spec.params.is_empty());
        assert_eq!(spec.operation, DuckDbOperation::Query);
        assert!(spec.read_file.is_none());
        assert!(spec.catalog_filters.argument_names().is_empty());
    }

    #[test]
    fn parses_list_tables_operation_with_filters() {
        let spec: DuckDbBackendSpec = serde_json::from_value(serde_json::json!({
            "database": ":memory:",
            "operation": "list_tables",
            "catalog_filters": { "schema": "main", "table_type_arg": "kind" },
        }))
        .unwrap();
        assert_eq!(spec.operation, DuckDbOperation::ListTables);
        assert!(spec.operation.is_catalog());
        assert_eq!(spec.operation.as_str(), "list_tables");
        assert_eq!(spec.catalog_filters.schema.as_deref(), Some("main"));
        assert_eq!(
            spec.catalog_filters.argument_names(),
            vec!["kind".to_owned()]
        );
        // `statement` may be omitted for non-query operations.
        assert!(spec.statement.is_empty());
    }

    #[test]
    fn parses_list_columns_operation() {
        let spec: DuckDbBackendSpec = serde_json::from_value(serde_json::json!({
            "database": ":memory:",
            "operation": "list_columns",
            "catalog_filters": { "table": "customers" },
        }))
        .unwrap();
        assert_eq!(spec.operation, DuckDbOperation::ListColumns);
        assert!(spec.operation.is_catalog());
        assert_eq!(spec.catalog_filters.table.as_deref(), Some("customers"));
    }

    #[test]
    fn parses_read_file_operation() {
        let spec: DuckDbBackendSpec = serde_json::from_value(serde_json::json!({
            "database": ":memory:",
            "operation": "read_file",
            "allow_external_access": true,
            "read_file": {
                "path": "/data/sales/*.parquet",
                "format": "parquet",
                "columns": ["region", "amount"],
                "predicate": "amount > ?",
            },
        }))
        .unwrap();
        assert_eq!(spec.operation, DuckDbOperation::ReadFile);
        assert!(!spec.operation.is_catalog());
        let rf = spec.read_file.expect("read_file");
        assert_eq!(rf.path, "/data/sales/*.parquet");
        assert_eq!(rf.format, ReadFileFormat::Parquet);
        assert_eq!(rf.format.table_function(), "read_parquet");
        assert_eq!(rf.columns, vec!["region".to_owned(), "amount".to_owned()]);
        assert_eq!(rf.predicate.as_deref(), Some("amount > ?"));
    }

    #[test]
    fn read_file_format_csv_maps_to_read_csv_auto() {
        assert_eq!(ReadFileFormat::Csv.table_function(), "read_csv_auto");
        assert_eq!(ReadFileFormat::default(), ReadFileFormat::Parquet);
    }

    #[test]
    fn validate_read_file_enforces_path_columns_and_cred() {
        let mut cfg = ReadFileConfig {
            path: "/data/x.parquet".into(),
            format: ReadFileFormat::Parquet,
            columns: vec!["a".into(), "b".into()],
            predicate: Some("a > ?".into()),
        };
        assert!(validate_read_file(&cfg).is_ok());

        cfg.path = "  ".into();
        assert!(validate_read_file(&cfg).is_err(), "empty path");

        cfg.path = "s3://b/cred://aws/x#k".into();
        assert!(validate_read_file(&cfg).is_err(), "bare cred:// in path");

        cfg.path = "/data/x.parquet".into();
        cfg.columns = vec!["a; DROP TABLE t".into()];
        assert!(
            validate_read_file(&cfg).is_err(),
            "unsafe projection identifier"
        );

        cfg.columns = vec![];
        cfg.predicate = Some("  ".into());
        assert!(
            validate_read_file(&cfg).is_err(),
            "empty predicate when set"
        );
    }

    #[test]
    fn parses_overrides_and_attach() {
        let spec: DuckDbBackendSpec = serde_json::from_value(serde_json::json!({
            "database": "/data/warehouse.duckdb",
            "read_only": false,
            "allow_external_access": true,
            "init_sql": ["INSTALL httpfs; LOAD httpfs;"],
            "attach": [{ "alias": "lake", "source": "s3://bucket/db.duckdb", "read_only": true }],
            "statement": "SELECT * FROM read_parquet(?)",
            "params": ["arguments.path"],
            "query": { "statement_timeout_ms": 5000, "max_rows": 50 },
        }))
        .unwrap();
        assert!(!spec.read_only);
        assert!(spec.allow_external_access);
        assert_eq!(spec.init_sql.len(), 1);
        assert_eq!(spec.attach.len(), 1);
        assert_eq!(spec.attach[0].alias, "lake");
        assert!(spec.attach[0].read_only);
        assert_eq!(spec.query.statement_timeout_ms, 5000);
        assert_eq!(spec.query.max_rows, 50);
    }

    #[test]
    fn parses_list_query_and_completions() {
        let spec: DuckDbBackendSpec = serde_json::from_value(serde_json::json!({
            "database": ":memory:",
            "statement": "SELECT 1 AS one",
            "surface": "resource",
            "list_query": {
                "sql": "SELECT id AS uri FROM t WHERE id > ? ORDER BY id LIMIT ?",
                "cursor_column": "id",
                "page_size": 50,
            },
            "variable_completions": {
                "name": { "sql": "SELECT name FROM t WHERE name LIKE ? || '%' LIMIT 100" },
            },
        }))
        .unwrap();
        let lq = spec.list_query.expect("list_query");
        assert_eq!(lq.page_size, 50);
        assert_eq!(lq.mode, ListQueryMode::Keyset);
        assert_eq!(lq.cursor_column.as_deref(), Some("id"));
        assert!(spec.variable_completions.contains_key("name"));
    }

    #[test]
    fn parses_resource_template_read_query() {
        let spec: DuckDbBackendSpec = serde_json::from_value(serde_json::json!({
            "database": ":memory:",
            "surface": "resource",
            "read_query": "SELECT * FROM orders WHERE id = ?",
            "params": ["arguments.id"],
        }))
        .unwrap();
        assert_eq!(
            spec.read_query.as_deref(),
            Some("SELECT * FROM orders WHERE id = ?")
        );
        // `statement` may be omitted when `read_query` carries the read.
        assert!(spec.statement.is_empty());
        assert_eq!(spec.params, vec!["arguments.id".to_owned()]);
    }

    #[test]
    fn read_query_defaults_to_none() {
        let spec: DuckDbBackendSpec = serde_json::from_value(serde_json::json!({
            "database": ":memory:",
            "statement": "SELECT 1 AS one",
        }))
        .unwrap();
        assert!(spec.read_query.is_none());
    }

    #[test]
    fn validate_list_query_enforces_bounds_and_cursor() {
        let mut cfg = ListQueryConfig {
            sql: "SELECT id AS uri FROM t".into(),
            mode: ListQueryMode::Keyset,
            cursor_column: None,
            page_size: 100,
        };
        assert!(
            validate_list_query(&cfg).is_err(),
            "keyset needs cursor_column"
        );
        cfg.cursor_column = Some("id".into());
        assert!(validate_list_query(&cfg).is_ok());
        cfg.cursor_column = Some("id; DROP TABLE t".into());
        assert!(
            validate_list_query(&cfg).is_err(),
            "unsafe cursor identifier"
        );
        cfg.cursor_column = Some("id".into());
        cfg.page_size = 0;
        assert!(validate_list_query(&cfg).is_err(), "page_size out of range");
        cfg.page_size = 100;
        cfg.sql = "  ".into();
        assert!(validate_list_query(&cfg).is_err(), "empty sql");
    }

    #[test]
    fn validate_list_query_offset_mode_skips_cursor() {
        let cfg = ListQueryConfig {
            sql: "SELECT id AS uri FROM t LIMIT ? OFFSET ?".into(),
            mode: ListQueryMode::Offset,
            cursor_column: None,
            page_size: 100,
        };
        assert!(validate_list_query(&cfg).is_ok());
    }

    #[test]
    fn validate_completion_requires_single_placeholder() {
        let mut cc = CompletionConfig {
            sql: "SELECT name FROM t WHERE name LIKE ? || '%'".into(),
            max_results: None,
        };
        assert!(validate_completion("name", &cc).is_ok());
        cc.sql = "SELECT name FROM t".into();
        assert!(validate_completion("name", &cc).is_err(), "needs one ?");
        cc.sql = "SELECT name FROM t WHERE a = ? AND b = ?".into();
        assert!(validate_completion("name", &cc).is_err(), "exactly one ?");
        cc.sql = "  ".into();
        assert!(validate_completion("name", &cc).is_err(), "empty sql");
    }
}
