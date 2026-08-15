//! DuckDB embedded-OLAP backend binding plugin for mcpg.
//!
//! Implements [`DuckDbBackendPlugin`] — `BackendPlugin` for `kind: "duckdb"`.
//! Runs an operator-fixed analytical statement whose `?` placeholders are bound
//! from CEL expressions evaluated against the tool arguments (bound as SQL
//! parameters, never interpolated — injection-safe), against an embedded DuckDB
//! engine (`:memory:` or a file). A read-only keyword guard and an
//! external-access default-deny guard fence the engine's filesystem / network
//! reach. Structurally mirrors the oracle/snowflake backends; DuckDB-specific
//! machinery lives in [`duckdb`] + [`params`] + [`envelope`].
//!
//! **File** databases reuse connections through a lazy `deadpool` pool (built at
//! register, opened on first use); `:memory:` databases are opened per call so
//! each call gets a fresh ephemeral engine (`:memory:` is never pooled — see the
//! `database` field docs and the README).

use std::collections::BTreeMap;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use mcpg_plugin_protocol::audit::{AuditEvent, AuditOutcome};
use mcpg_plugin_protocol::types::PluginIdentity;
use mcpg_plugin_protocol::{
    BackendError, BackendHost, BackendPlugin, BackendRequest, BackendResponse, PluginManifest,
    firstparty_manifest,
};
use mcpg_plugin_sdk::{HostHandle, SpanGuard};
use serde_json::{Value, json};
use tokio::sync::RwLock;
use tracing::debug;

/// cdylib sync bridge.
pub mod cdylib;
mod duckdb;
mod envelope;
mod params;
mod surface;
mod types;
pub mod watch;

use duckdb::{
    CatalogFilters, DuckDbManager, DuckDbPool, QueryOutcome, build_list_columns_sql,
    build_list_tables_sql, build_pool, build_read_file_sql, enforce_read_only, run_query_blocking,
    run_query_on_conn, valid_attach_alias,
};
use envelope::{build_result_envelope, classify_error};
use mcpg_plugin_protocol::ResourcePage;
use params::{CompiledParam, DuckBind, compile_params, evaluate_params, json_to_duck_bind};
pub use types::{
    CatalogFilterConfig as DuckDbCatalogFilterConfig, CompletionConfig as DuckDbCompletionConfig,
    DuckDbAttach, DuckDbBackendSpec, DuckDbOperation, DuckDbQueryConfig,
    ListQueryConfig as DuckDbListQueryConfig, ListQueryMode,
    ReadFileConfig as DuckDbReadFileConfig, ReadFileFormat, validate_completion,
    validate_list_query, validate_read_file,
};

/// Embedded plugin descriptor.
pub const BINDING_DESCRIPTOR_YAML: &str = include_str!("../plugin.yaml");

// --------------------------------------------------------------------- obs

fn audit_action_for_outcome(label: &str) -> Option<&'static str> {
    match label {
        "timeout" => Some("dev.mcpg.backend.duckdb.request_timeout"),
        "transport_error" => Some("dev.mcpg.backend.duckdb.request_failed"),
        "duckdb_error" => Some("dev.mcpg.backend.duckdb.query_rejected"),
        "invalid_spec" => Some("dev.mcpg.backend.duckdb.request_failed"),
        _ => None,
    }
}

fn rfc3339_now() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

fn synthetic_system_identity() -> PluginIdentity {
    PluginIdentity {
        kind: "system".into(),
        trust_level: "verified".into(),
        subject_id: Some("dev.mcpg.backend.duckdb".into()),
        auth_provider: None,
        issuer: None,
        roles: vec![],
        groups: vec![],
        scopes: vec![],
        attributes: Default::default(),
    }
}

fn finalize_payload(envelope: Value) -> Result<BackendResponse, BackendError> {
    let payload = serde_json::to_vec(&envelope).map_err(|e| BackendError::Transport {
        message: format!("DuckDB plugin envelope serialization failed: {e}"),
    })?;
    Ok(BackendResponse {
        payload,
        truncated: false,
    })
}

/// Reject a bare `cred://` URI in an operator-fixed string. Secrets reach the
/// engine through `${cred://…}` resolved at config load (e.g. in `init_sql`'s
/// `CREATE SECRET`); a bare `cred://` would be sent to DuckDB verbatim, which is
/// always an operator mistake.
fn reject_bare_cred(field: &str, value: &str) -> Result<(), String> {
    if value.contains("cred://") {
        return Err(format!(
            "{field} must not contain a bare cred:// URI — use ${{cred://…}} (resolved at config load)"
        ));
    }
    Ok(())
}

// ------------------------------------------------------------------ plugin

/// Per-binding DuckDB runtime — connection parameters + compiled statement.
/// For a **file** database `pool` holds a lazy `deadpool` pool (opened on first
/// use) whose connections are reused across calls. For `:memory:` `pool` is
/// `None` and each call opens a fresh ephemeral engine via
/// [`duckdb::run_query_blocking`]. Cheap to clone (pool/init/attach/params
/// behind `Arc`).
#[derive(Clone)]
struct DuckDbProfile {
    /// `Some` for a file database (pooled); `None` for `:memory:` (per-call).
    pool: Option<Arc<DuckDbPool>>,
    database: String,
    read_only: bool,
    allow_external_access: bool,
    init_sql: Arc<[String]>,
    attach: Arc<[DuckDbAttach]>,
    operation: DuckDbOperation,
    statement: String,
    /// Catalog-introspection filter config; consulted only for the
    /// `list_tables` / `list_columns` operations.
    catalog_filters: Arc<DuckDbCatalogFilterConfig>,
    /// Resolved external-file read config; `Some` only for `operation: read_file`.
    read_file: Option<Arc<DuckDbReadFileConfig>>,
    compiled_params: Arc<[CompiledParam]>,
    max_rows: usize,
    timeout: Duration,
    surface: surface::Surface,
    surface_uri: Option<String>,
    list_query: Option<DuckDbListQueryConfig>,
    /// Per-`{id}` single-row read statement for a `resource_templates[]` binding.
    /// Bound from the same `compiled_params` as `statement`; when None the
    /// resource-read branch falls back to `statement`. Only consulted for the
    /// default `operation: query` resource-read path.
    read_query: Option<String>,
    variable_completions: Arc<BTreeMap<String, DuckDbCompletionConfig>>,
}

/// `BackendPlugin` implementation for `kind: "duckdb"`.
pub struct DuckDbBackendPlugin {
    manifest: PluginManifest,
    profiles: RwLock<BTreeMap<String, DuckDbProfile>>,
    host_handle: OnceLock<HostHandle>,
}

impl Default for DuckDbBackendPlugin {
    fn default() -> Self {
        Self::new()
    }
}

impl DuckDbBackendPlugin {
    #[must_use]
    pub fn new() -> Self {
        Self {
            manifest: firstparty_manifest! {
                id: "dev.mcpg.backend.duckdb",
                name: "DuckDB Binding",
                class: Backend,
            },
            profiles: RwLock::new(BTreeMap::new()),
            host_handle: OnceLock::new(),
        }
    }

    pub fn set_host_handle(&self, host: HostHandle) -> bool {
        self.host_handle.set(host).is_ok()
    }

    fn host_handle(&self) -> Option<&HostHandle> {
        self.host_handle.get()
    }

    /// Per-call observability triad (latency + counter + optional audit).
    async fn emit_host_observability(
        &self,
        backend_name: &str,
        outcome_label: &'static str,
        reason: Option<&str>,
        identity: Option<&PluginIdentity>,
        request_id: &str,
        duration: Duration,
    ) {
        let Some(host) = self.host_handle() else {
            return;
        };
        host.histogram(
            "mcpg_duckdb_backend_latency_seconds",
            duration.as_secs_f64(),
            &[("outcome", outcome_label)],
        );
        host.counter(
            "mcpg_duckdb_backend_calls_total",
            1,
            &[("outcome", outcome_label)],
        );
        if let Some(action) = audit_action_for_outcome(outcome_label) {
            let actor = identity.cloned().unwrap_or_else(synthetic_system_identity);
            let mut details = json!({
                "backend": backend_name,
                "duration_ms": duration.as_millis() as u64,
                "outcome": outcome_label,
                "alias": host.alias(),
            });
            if let Some(reason) = reason {
                details
                    .as_object_mut()
                    .expect("json object")
                    .insert("reason".into(), Value::String(reason.to_owned()));
            }
            let event = AuditEvent {
                event_id: format!("duckdb-{}-{}", request_id, duration.as_nanos()),
                occurred_at: rfc3339_now(),
                actor,
                action: action.to_owned(),
                resource: Some(format!("duckdb-binding://{backend_name}")),
                outcome: AuditOutcome::Failure,
                request_id: Some(request_id.to_owned()),
                node_id: None,
                details,
                prev_event_hash: None,
            };
            let host_for_audit = host.clone();
            if let Err(join_err) = tokio::task::spawn_blocking(move || {
                let _ = host_for_audit.audit_event(event);
            })
            .await
            {
                debug!(target: "mcpg::duckdb::host_handle", error = %join_err, "audit spawn_blocking failed");
            }
        }
    }

    /// Build an error envelope (param-eval failures), emit the triad, and return
    /// it as a normal payload — matching the oracle/snowflake backends.
    #[allow(clippy::too_many_arguments)]
    async fn finish_error(
        &self,
        profile: &DuckDbProfile,
        backend_name: &str,
        tool_name: &str,
        message: &str,
        label: &'static str,
        identity: Option<&PluginIdentity>,
        request_id: &str,
        started: Instant,
        host_span: Option<SpanGuard>,
    ) -> Result<BackendResponse, BackendError> {
        let downstream = classify_error(message);
        let envelope = build_result_envelope(
            tool_name,
            backend_name,
            &profile.database,
            None,
            None,
            false,
            started.elapsed().as_millis(),
            Some(&downstream),
            Some(message),
        );
        self.emit_host_observability(
            backend_name,
            label,
            Some(message),
            identity,
            request_id,
            started.elapsed(),
        )
        .await;
        drop(host_span);
        finalize_payload(envelope)
    }

    /// Run a statement for `profile`, choosing the connection strategy by
    /// database: a **file** DB draws a connection from the lazy pool (reused
    /// across calls) and runs the query on it; `:memory:` opens a fresh
    /// ephemeral engine per call (re-running init_sql / attach each time). Both
    /// run on a blocking thread under the outer tokio timeout (applied by the
    /// caller). The pooled `Object` is `Send`, so it is moved into the closure
    /// and dropped back to the pool when the statement completes.
    async fn run_query(
        &self,
        profile: &DuckDbProfile,
        statement: &str,
        bound: Vec<params::DuckBind>,
        max_rows: usize,
    ) -> Result<QueryOutcome, String> {
        match &profile.pool {
            Some(pool) => {
                let conn = match tokio::time::timeout(profile.timeout, pool.get()).await {
                    Ok(Ok(c)) => c,
                    Ok(Err(e)) => return Err(format!("DuckDB pool acquire failed: {e}")),
                    Err(_) => return Err("DuckDB pool acquire timed out".to_owned()),
                };
                let statement = statement.to_owned();
                let blocking = tokio::task::spawn_blocking(move || {
                    // `conn` (the pooled Object) is moved in and dropped here,
                    // returning the connection to the pool.
                    run_query_on_conn(&conn, &statement, bound, max_rows)
                });
                match tokio::time::timeout(profile.timeout, blocking).await {
                    Ok(Ok(inner)) => inner,
                    Ok(Err(join_err)) => Err(format!("DuckDB worker task failed: {join_err}")),
                    Err(_) => Err("DuckDB call timed out".to_owned()),
                }
            }
            None => {
                // `:memory:` — open a fresh ephemeral engine per call.
                let database = profile.database.clone();
                let read_only = profile.read_only;
                let allow_external_access = profile.allow_external_access;
                let init_sql: Vec<String> = profile.init_sql.to_vec();
                let attach: Vec<DuckDbAttach> = profile.attach.to_vec();
                let statement = statement.to_owned();
                let blocking = tokio::task::spawn_blocking(move || {
                    run_query_blocking(
                        &database,
                        read_only,
                        allow_external_access,
                        &init_sql,
                        &attach,
                        &statement,
                        bound,
                        max_rows,
                    )
                });
                match tokio::time::timeout(profile.timeout, blocking).await {
                    Ok(Ok(inner)) => inner,
                    Ok(Err(join_err)) => Err(format!("DuckDB worker task failed: {join_err}")),
                    Err(_) => Err("DuckDB call timed out".to_owned()),
                }
            }
        }
    }
}

impl std::fmt::Debug for DuckDbBackendPlugin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DuckDbBackendPlugin")
            .field("id", &self.manifest.id)
            .finish()
    }
}

#[async_trait]
impl BackendPlugin for DuckDbBackendPlugin {
    fn manifest(&self) -> &PluginManifest {
        &self.manifest
    }

    fn kind(&self) -> &str {
        "duckdb"
    }

    async fn register_profile(
        &self,
        backend_name: &str,
        spec: &Value,
        _host: Arc<dyn BackendHost>,
    ) -> Result<(), BackendError> {
        let parsed: DuckDbBackendSpec =
            serde_json::from_value(spec.clone()).map_err(|e| BackendError::InvalidSpec {
                message: format!("DuckDB binding spec: {e}"),
            })?;

        let invalid = |m: String| BackendError::InvalidSpec { message: m };
        if parsed.database.trim().is_empty() {
            return Err(invalid("database must not be empty".into()));
        }
        // `statement` is required only for `operation: query`; the catalog /
        // read_file operations drive their own builders and ignore it.
        match parsed.operation {
            DuckDbOperation::Query => {
                // A resource_template binding may supply only `read_query` (the
                // per-`{id}` single-row read) and omit `statement`; otherwise the
                // operator-fixed `statement` is required.
                if parsed.statement.trim().is_empty()
                    && parsed
                        .read_query
                        .as_deref()
                        .map(str::trim)
                        .unwrap_or("")
                        .is_empty()
                {
                    return Err(invalid(
                        "statement must not be empty (or set `read_query` for a resource_template read binding)".into(),
                    ));
                }
            }
            DuckDbOperation::ListColumns => {
                // Listing every column of every table is almost never the
                // intent; require a `table` filter or a per-call `table_arg`.
                let has_table = parsed
                    .catalog_filters
                    .table
                    .as_deref()
                    .map(str::trim)
                    .is_some_and(|s| !s.is_empty())
                    || parsed
                        .catalog_filters
                        .table_arg
                        .as_deref()
                        .map(str::trim)
                        .is_some_and(|s| !s.is_empty());
                if !has_table {
                    return Err(invalid(
                        "operation: list_columns requires a catalog_filters.table or .table_arg (the table whose columns to list)".into(),
                    ));
                }
            }
            DuckDbOperation::ListTables => {}
            DuckDbOperation::ReadFile => {
                let cfg = parsed.read_file.as_ref().ok_or_else(|| {
                    invalid("operation: read_file requires a `read_file` config block".into())
                })?;
                validate_read_file(cfg).map_err(invalid)?;
                // External-file reads inherently touch the filesystem / network,
                // which the external-access default-deny fences. Reject up front
                // when access is off so the binding never silently fails per call.
                if !parsed.allow_external_access {
                    return Err(invalid(
                        "operation: read_file requires allow_external_access=true (it reads files outside the database)".into(),
                    ));
                }
                // The read_file predicate is operator-fixed and read-only.
                if let Some(pred) = cfg.predicate.as_deref() {
                    reject_bare_cred("read_file.predicate", pred).map_err(invalid)?;
                }
            }
        }
        if parsed.query.statement_timeout_ms == 0 {
            return Err(invalid(
                "query.statement_timeout_ms must be greater than 0".into(),
            ));
        }
        if parsed.query.max_rows == 0 {
            return Err(invalid("query.max_rows must be greater than 0".into()));
        }
        if parsed.pool_max_size == 0 {
            return Err(invalid("pool_max_size must be greater than 0".into()));
        }
        reject_bare_cred("database", &parsed.database).map_err(invalid)?;
        reject_bare_cred("statement", &parsed.statement).map_err(invalid)?;
        for (i, sql) in parsed.init_sql.iter().enumerate() {
            reject_bare_cred(&format!("init_sql[{i}]"), sql).map_err(invalid)?;
        }
        for a in &parsed.attach {
            if !valid_attach_alias(&a.alias) {
                return Err(invalid(format!(
                    "attach alias `{}` must match [A-Za-z_][A-Za-z0-9_]*",
                    a.alias
                )));
            }
            reject_bare_cred(&format!("attach[{}].source", a.alias), &a.source).map_err(invalid)?;
        }
        // Read-only guard applies to the `query` statement only: the catalog /
        // read_file operations build read-only SELECTs themselves and never
        // mutate, so the keyword guard would have nothing to check. The guard
        // runs on a present `statement`; a resource_template read binding may
        // omit it (the per-`{id}` read lives in `read_query`, guarded below).
        if parsed.operation == DuckDbOperation::Query
            && parsed.read_only
            && !parsed.statement.trim().is_empty()
        {
            enforce_read_only(&parsed.statement).map_err(invalid)?;
        }

        // Surface coherence: `uri` is only meaningful on the resource surface;
        // a static `uri` on a tool/prompt binding is a config mistake worth a
        // fail-closed rejection at register rather than a silent no-op.
        if parsed.uri.is_some() && parsed.surface != surface::Surface::Resource {
            return Err(invalid(format!(
                "`uri` is only valid with `surface: resource` (this binding is `surface: {}`)",
                parsed.surface.as_str()
            )));
        }
        if let Some(u) = &parsed.uri
            && u.trim().is_empty()
        {
            return Err(invalid("`uri` must not be empty".into()));
        }

        // `read_query` is the per-`{id}` single-row read for a resource_template
        // binding; like `statement` it is operator-fixed, must be read-only under
        // the guard, and must not carry a bare cred://. It only makes sense on the
        // resource surface — fail-closed elsewhere so a misplaced field is never a
        // silent no-op.
        if let Some(rq) = &parsed.read_query {
            if rq.trim().is_empty() {
                return Err(invalid("`read_query` must not be empty".into()));
            }
            if parsed.surface != surface::Surface::Resource {
                return Err(invalid(format!(
                    "`read_query` is only valid with `surface: resource` (this binding is `surface: {}`)",
                    parsed.surface.as_str()
                )));
            }
            reject_bare_cred("read_query", rq).map_err(invalid)?;
            if parsed.read_only {
                enforce_read_only(rq).map_err(invalid)?;
            }
        }

        // Listing + completion are operator-fixed read surfaces; fail-closed at
        // register so a misconfigured `list_query` / `variable_completions`
        // never reaches a `resources/list` or `completion/complete` call.
        if let Some(lq) = &parsed.list_query {
            validate_list_query(lq).map_err(invalid)?;
            reject_bare_cred("list_query.sql", &lq.sql).map_err(invalid)?;
            if parsed.read_only {
                enforce_read_only(&lq.sql).map_err(invalid)?;
            }
        }
        for (name, cc) in &parsed.variable_completions {
            validate_completion(name, cc).map_err(invalid)?;
            reject_bare_cred(&format!("variable_completions.{name}.sql"), &cc.sql)
                .map_err(invalid)?;
            if parsed.read_only {
                enforce_read_only(&cc.sql).map_err(invalid)?;
            }
        }

        let compiled_params: Arc<[CompiledParam]> =
            compile_params(&parsed.params).map_err(invalid)?.into();

        // File databases are pooled (lazy — no connection opened here, so
        // register stays I/O-free). `:memory:` is never pooled: each call opens
        // a fresh ephemeral engine that init_sql re-seeds, so pooling it would
        // silently make it persistent/shared. Keep `pool = None` for `:memory:`.
        let is_memory = parsed.database == ":memory:";
        let pool: Option<Arc<DuckDbPool>> = if is_memory {
            None
        } else {
            let manager = DuckDbManager::new(
                parsed.database.clone(),
                parsed.read_only,
                parsed.allow_external_access,
                parsed.init_sql.clone(),
                parsed.attach.clone(),
            );
            Some(Arc::new(
                build_pool(manager, parsed.pool_max_size).map_err(invalid)?,
            ))
        };

        debug!(
            backend = %backend_name,
            database = %parsed.database,
            read_only = parsed.read_only,
            external_access = parsed.allow_external_access,
            pooled = pool.is_some(),
            params = compiled_params.len(),
            "registered DuckDB binding profile"
        );

        self.profiles.write().await.insert(
            backend_name.to_owned(),
            DuckDbProfile {
                pool,
                database: parsed.database,
                read_only: parsed.read_only,
                allow_external_access: parsed.allow_external_access,
                init_sql: parsed.init_sql.into(),
                attach: parsed.attach.into(),
                operation: parsed.operation,
                statement: parsed.statement,
                catalog_filters: Arc::new(parsed.catalog_filters),
                read_file: parsed.read_file.map(Arc::new),
                compiled_params,
                max_rows: parsed.query.max_rows,
                timeout: Duration::from_millis(parsed.query.statement_timeout_ms),
                surface: parsed.surface,
                surface_uri: parsed.uri,
                list_query: parsed.list_query,
                read_query: parsed.read_query,
                variable_completions: Arc::new(parsed.variable_completions),
            },
        );
        Ok(())
    }

    async fn execute(
        &self,
        backend_name: &str,
        request: BackendRequest,
    ) -> Result<BackendResponse, BackendError> {
        let started = Instant::now();
        let request_id = request.request_id.clone();
        let identity = request.identity.clone();
        let host_span = self.host_handle().map(|h| {
            h.span(
                "duckdb_backend.execute",
                json!({ "backend": backend_name, "request_id": request_id }),
            )
        });

        let profile = {
            let guard = self.profiles.read().await;
            match guard.get(backend_name).cloned() {
                Some(p) => p,
                None => {
                    let err = BackendError::ProfileNotFound {
                        backend_name: backend_name.to_owned(),
                    };
                    self.emit_host_observability(
                        backend_name,
                        "profile_not_found",
                        Some(&err.to_string()),
                        identity.as_ref(),
                        &request_id,
                        started.elapsed(),
                    )
                    .await;
                    drop(host_span);
                    return Err(err);
                }
            }
        };

        let arguments: Value = if request.payload.is_empty() {
            json!({})
        } else {
            match serde_json::from_slice(&request.payload) {
                Ok(v) => v,
                Err(e) => {
                    let err = BackendError::InvalidSpec {
                        message: format!("DuckDB plugin payload is not valid JSON: {e}"),
                    };
                    self.emit_host_observability(
                        backend_name,
                        "invalid_spec",
                        Some(&err.to_string()),
                        identity.as_ref(),
                        &request_id,
                        started.elapsed(),
                    )
                    .await;
                    drop(host_span);
                    return Err(err);
                }
            }
        };

        let tool_name = request
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("mcpg-tool-name"))
            .map(|(_, v)| v.clone())
            .unwrap_or_else(|| backend_name.to_owned());

        // Resolve the statement + binds for this operation. `query` / `read_file`
        // evaluate the CEL `params` (lowered to scalar binds); the catalog ops
        // bypass CEL entirely and bind their resolved filters. The read_file path
        // is operator-fixed — caller args reach it only as bound predicate
        // values, never as a path or interpolated SQL.
        let (statement, bound): (String, Vec<DuckBind>) = match profile.operation {
            DuckDbOperation::ListTables => {
                let filters = resolve_catalog_filters(&profile.catalog_filters, &arguments);
                build_list_tables_sql(&filters)
            }
            DuckDbOperation::ListColumns => {
                let filters = resolve_catalog_filters(&profile.catalog_filters, &arguments);
                build_list_columns_sql(&filters)
            }
            DuckDbOperation::Query | DuckDbOperation::ReadFile => {
                let bound = match eval_param_binds(&profile.compiled_params, &arguments) {
                    Ok(b) => b,
                    Err(message) => {
                        return self
                            .finish_error(
                                &profile,
                                backend_name,
                                &tool_name,
                                &message,
                                "invalid_spec",
                                identity.as_ref(),
                                &request_id,
                                started,
                                host_span,
                            )
                            .await;
                    }
                };
                let statement = match profile.operation {
                    DuckDbOperation::ReadFile => {
                        // SAFETY: read_file is `Some` for this op (enforced at
                        // register); path/columns are operator-fixed + validated.
                        let rf = profile
                            .read_file
                            .as_ref()
                            .expect("read_file config present for read_file op");
                        build_read_file_sql(
                            rf.format.table_function(),
                            &rf.path,
                            &rf.columns,
                            rf.predicate.as_deref(),
                        )
                    }
                    // Default query op: on the resource surface a per-`{id}`
                    // `read_query` (when configured) is the single-row read for a
                    // `resource_templates[]` binding; it binds the same `params`
                    // (the gateway-extracted template vars reach it as
                    // `arguments.<var>`). Every other case runs the operator-fixed
                    // `statement`.
                    _ => match (profile.surface, profile.read_query.as_deref()) {
                        (surface::Surface::Resource, Some(rq)) => rq.to_owned(),
                        _ => profile.statement.clone(),
                    },
                };
                (statement, bound)
            }
        };

        // DuckDB is blocking + compiled-in; file DBs reuse a pooled connection,
        // `:memory:` opens a fresh ephemeral engine per call. Both run on a
        // blocking thread under the outer tokio timeout.
        let result: Result<QueryOutcome, String> = self
            .run_query(&profile, &statement, bound, profile.max_rows)
            .await;

        let (envelope, outcome_label, audit_reason): (Value, &'static str, Option<String>) =
            match result {
                Ok(outcome) => {
                    // On the resource/prompt surfaces the gateway decoder
                    // requires a surface-shaped body; the tool surface keeps the
                    // historical envelope. A resource read with no resolvable URI
                    // falls back to the tool error envelope (carries
                    // `downstreamError` → gateway `is_error`) so the decoder sees
                    // a clean error rather than an invalid `{contents}`.
                    match profile.surface {
                        surface::Surface::Tool => (
                            build_result_envelope(
                                &tool_name,
                                backend_name,
                                &profile.database,
                                Some(&outcome.rows),
                                Some(outcome.row_count),
                                outcome.truncated,
                                started.elapsed().as_millis(),
                                None,
                                None,
                            ),
                            "ok",
                            None,
                        ),
                        surface::Surface::Resource => {
                            match surface::resolve_resource_uri(
                                profile.surface_uri.as_deref(),
                                &arguments,
                            ) {
                                Some(uri) => (
                                    surface::resource_contents_body(uri, &outcome.rows),
                                    "ok",
                                    None,
                                ),
                                None => {
                                    let message = "resource surface requires a `uri` (set a static `uri` on the binding or invoke via a resources/read request)".to_owned();
                                    let downstream = classify_error(&message);
                                    let env = build_result_envelope(
                                        &tool_name,
                                        backend_name,
                                        &profile.database,
                                        None,
                                        None,
                                        false,
                                        started.elapsed().as_millis(),
                                        Some(&downstream),
                                        Some(&message),
                                    );
                                    (env, "duckdb_error", Some(message))
                                }
                            }
                        }
                        surface::Surface::Prompt => {
                            (surface::prompt_messages_body(&outcome.rows), "ok", None)
                        }
                    }
                }
                Err(message) => {
                    let downstream = classify_error(&message);
                    let lower = message.to_ascii_lowercase();
                    let label = if lower.contains("timed out") || lower.contains("timeout") {
                        "timeout"
                    } else if downstream["kind"] == json!("transport_error") {
                        "transport_error"
                    } else {
                        "duckdb_error"
                    };
                    let env = build_result_envelope(
                        &tool_name,
                        backend_name,
                        &profile.database,
                        None,
                        None,
                        false,
                        started.elapsed().as_millis(),
                        Some(&downstream),
                        Some(&message),
                    );
                    (env, label, Some(message))
                }
            };

        self.emit_host_observability(
            backend_name,
            outcome_label,
            audit_reason.as_deref(),
            identity.as_ref(),
            &request_id,
            started.elapsed(),
        )
        .await;
        drop(host_span);
        finalize_payload(envelope)
    }

    fn audit_metadata(&self, _backend_name: &str) -> serde_json::Map<String, Value> {
        let mut map = serde_json::Map::new();
        map.insert("duckdb.transport".to_owned(), json!("plugin"));
        map
    }

    /// JSON Schema for the result envelope this binding emits. For the catalog
    /// operations the `response.rows` items are typed to the known
    /// `information_schema` column set; `query` / `read_file` leave rows untyped
    /// (any shape).
    fn output_schema(&self, backend_name: &str) -> Option<Value> {
        let op = self
            .profiles
            .try_read()
            .ok()
            .and_then(|g| g.get(backend_name).map(|p| p.operation))
            .unwrap_or(DuckDbOperation::Query);
        Some(match op {
            DuckDbOperation::ListTables => {
                envelope::catalog_envelope_schema(envelope::LIST_TABLES_COLUMNS)
            }
            DuckDbOperation::ListColumns => {
                envelope::catalog_envelope_schema(envelope::LIST_COLUMNS_COLUMNS)
            }
            DuckDbOperation::Query | DuckDbOperation::ReadFile => {
                envelope::result_envelope_schema()
            }
        })
    }

    /// JSON Schema for the tool arguments. For `query` / `read_file` the
    /// positional `params` are CEL expressions over `arguments.*`; the referenced
    /// argument names are surfaced as untyped, optional properties. For the
    /// catalog ops the callable args are the configured `*_arg` filter names
    /// (`read_file` exposes NO path argument — the path is operator-config only).
    /// The object stays open (`additionalProperties: true`) so the schema never
    /// rejects valid args.
    fn input_schema(&self, backend_name: &str) -> Option<Value> {
        // `try_read` (sync, non-blocking): `input_schema` is called from the
        // gateway's registration path with no concurrent writer.
        let names: Vec<String> = self
            .profiles
            .try_read()
            .ok()
            .and_then(|g| {
                g.get(backend_name).map(|p| {
                    if p.operation.is_catalog() {
                        p.catalog_filters.argument_names()
                    } else {
                        arguments_referenced_by_params(&p.compiled_params)
                    }
                })
            })
            .unwrap_or_default();
        Some(params_input_schema(&names))
    }

    /// Enumerate resources for `resources/list` via the operator-fixed
    /// `list_query`. Bindings without one inherit the empty page. The
    /// pagination `?cursor` / `?page_size` are the only non-operator binds:
    /// keyset binds the prior page's last `cursor_column` (NULL first page),
    /// offset binds page_size then the running offset.
    async fn list_resources(
        &self,
        backend_name: &str,
        cursor: Option<&str>,
    ) -> Result<ResourcePage, BackendError> {
        let profile = {
            let guard = self.profiles.read().await;
            guard
                .get(backend_name)
                .cloned()
                .ok_or_else(|| BackendError::ProfileNotFound {
                    backend_name: backend_name.to_owned(),
                })?
        };
        let Some(list_cfg) = profile.list_query.clone() else {
            return Ok(ResourcePage::empty());
        };

        // Bind the cursor + page_size in the order DuckDB sees the two `?`s for
        // the active mode. Keyset: `(cursor, page_size)`; offset:
        // `(page_size, offset)`.
        let prior_offset = match (list_cfg.mode, cursor) {
            (ListQueryMode::Offset, Some(c)) => {
                c.parse::<u64>().map_err(|_| BackendError::InvalidSpec {
                    message: format!("offset-mode cursor '{c}' is not a non-negative integer"),
                })?
            }
            _ => 0,
        };
        let binds: Vec<params::DuckBind> = match list_cfg.mode {
            ListQueryMode::Keyset => vec![
                match cursor {
                    Some(c) => params::DuckBind::Str(c.to_owned()),
                    None => params::DuckBind::Null,
                },
                params::DuckBind::Int(list_cfg.page_size as i64),
            ],
            ListQueryMode::Offset => vec![
                params::DuckBind::Int(list_cfg.page_size as i64),
                params::DuckBind::Int(prior_offset as i64),
            ],
        };

        let outcome = self
            .run_query(&profile, &list_cfg.sql, binds, list_cfg.page_size as usize)
            .await
            .map_err(|message| BackendError::Transport { message })?;

        Ok(surface::rows_to_resource_page(
            &outcome.rows,
            &list_cfg,
            prior_offset,
        ))
    }

    /// Return completion candidates for a resource-template variable via the
    /// operator-fixed `variable_completions[<variable_name>]` query. The single
    /// `?` is bound to the caller's typed `prefix` value — never interpolated.
    /// Unconfigured variables inherit the empty list.
    async fn complete_template_variable(
        &self,
        backend_name: &str,
        variable_name: &str,
        prefix: &str,
        _config: &Value,
        _context: &BTreeMap<String, String>,
    ) -> Result<Vec<String>, BackendError> {
        let profile = {
            let guard = self.profiles.read().await;
            guard
                .get(backend_name)
                .cloned()
                .ok_or_else(|| BackendError::ProfileNotFound {
                    backend_name: backend_name.to_owned(),
                })?
        };
        let Some(cc) = profile.variable_completions.get(variable_name).cloned() else {
            return Ok(vec![]);
        };

        let max = cc.max_results.unwrap_or(100) as usize;
        let binds = vec![params::DuckBind::Str(prefix.to_owned())];
        let outcome = self
            .run_query(&profile, &cc.sql, binds, max)
            .await
            .map_err(|message| BackendError::Transport { message })?;

        let first_col = outcome
            .rows
            .first()
            .and_then(Value::as_object)
            .and_then(|m| m.keys().next().cloned());
        Ok(surface::rows_to_completion_values(
            &outcome.rows,
            first_col.as_deref(),
            max,
        ))
    }
}

/// Evaluate the CEL parameter expressions against `arguments`, then lower each
/// to a scalar DuckDB bind (rejecting arrays/objects). Connection-free; the
/// error message is surfaced to the caller as an `invalid_spec` envelope.
fn eval_param_binds(params: &[CompiledParam], arguments: &Value) -> Result<Vec<DuckBind>, String> {
    let values =
        evaluate_params(params, arguments).map_err(|e| format!("evaluating params: {e}"))?;
    let mut binds = Vec::with_capacity(values.len());
    for v in values {
        binds.push(json_to_duck_bind(v).map_err(|e| format!("binding params: {e}"))?);
    }
    Ok(binds)
}

/// Resolve the catalog-introspection filters for one call. For each, the
/// per-call argument (when configured AND present as a JSON string) overrides
/// the operator-pinned static value; absent both, the filter is `None` (no
/// constraint). Resolved values are BOUND as `?` params by the SQL builders —
/// never interpolated — so caller input can only narrow the metadata.
fn resolve_catalog_filters(cfg: &DuckDbCatalogFilterConfig, arguments: &Value) -> CatalogFilters {
    CatalogFilters {
        catalog: resolve_one(
            cfg.catalog.as_deref(),
            cfg.catalog_arg.as_deref(),
            arguments,
        ),
        schema: resolve_one(cfg.schema.as_deref(), cfg.schema_arg.as_deref(), arguments),
        table: resolve_one(cfg.table.as_deref(), cfg.table_arg.as_deref(), arguments),
        table_type: resolve_one(
            cfg.table_type.as_deref(),
            cfg.table_type_arg.as_deref(),
            arguments,
        ),
    }
}

/// Resolve a single catalog filter: a caller-supplied string argument (when the
/// `arg_name` is configured and the argument is a JSON string) overrides the
/// operator-pinned `static_value`; absent both, `None` (no filter).
fn resolve_one(
    static_value: Option<&str>,
    arg_name: Option<&str>,
    arguments: &Value,
) -> Option<String> {
    if let Some(name) = arg_name
        && let Some(v) = arguments.get(name).and_then(Value::as_str)
    {
        return Some(v.to_owned());
    }
    static_value.map(str::to_owned)
}

/// Collect the distinct `arguments.<ident>` names referenced across a
/// binding's compiled CEL params, preserving first-seen order.
fn arguments_referenced_by_params(params: &[CompiledParam]) -> Vec<String> {
    let mut names = Vec::new();
    for p in params {
        for name in extract_argument_idents(&p.source) {
            if !names.contains(&name) {
                names.push(name);
            }
        }
    }
    names
}

/// Build an open object schema from the referenced argument names. With no
/// known names this is the permissive `{type:object, additionalProperties:true}`.
fn params_input_schema(names: &[String]) -> Value {
    let mut properties = serde_json::Map::new();
    for name in names {
        properties.insert(name.clone(), json!({}));
    }
    json!({
        "type": "object",
        "properties": Value::Object(properties),
        "additionalProperties": true,
    })
}

/// Extract identifiers appearing as `arguments.<ident>` in a CEL source
/// string. Pure string scan (no CEL deps) — a best-effort hint, never a
/// rejection surface.
fn extract_argument_idents(source: &str) -> Vec<String> {
    const MARKER: &str = "arguments.";
    let mut out = Vec::new();
    let bytes = source.as_bytes();
    let mut search_from = 0;
    while let Some(rel) = source[search_from..].find(MARKER) {
        let start = search_from + rel + MARKER.len();
        let mut end = start;
        while end < bytes.len() {
            let c = bytes[end];
            if c.is_ascii_alphanumeric() || c == b'_' {
                end += 1;
            } else {
                break;
            }
        }
        if end > start {
            out.push(source[start..end].to_owned());
        }
        search_from = end.max(search_from + rel + MARKER.len());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn no_op_host() -> Arc<dyn BackendHost> {
        Arc::new(NoOpHost)
    }

    fn minimal_spec() -> Value {
        json!({
            "database": ":memory:",
            "statement": "SELECT 1 AS one WHERE 1 = ?",
            "params": ["arguments.id"],
        })
    }

    /// Invoke a registered profile and return the decoded JSON envelope.
    async fn exec(plugin: &DuckDbBackendPlugin, profile: &str, args: Value) -> Value {
        let req = BackendRequest {
            payload: serde_json::to_vec(&args).unwrap(),
            headers: vec![("mcpg-tool-name".into(), profile.into())],
            request_id: "rq".into(),
            session_id: None,
            identity: None,
            idempotency: None,
        };
        let resp = plugin.execute(profile, req).await.expect("execute");
        serde_json::from_slice(&resp.payload).expect("envelope json")
    }

    #[test]
    fn kind_is_duckdb() {
        assert_eq!(DuckDbBackendPlugin::new().kind(), "duckdb");
    }

    #[test]
    fn manifest_id() {
        assert_eq!(
            DuckDbBackendPlugin::new().manifest().id,
            "dev.mcpg.backend.duckdb"
        );
    }

    #[test]
    fn extract_argument_idents_finds_names() {
        let got = extract_argument_idents("arguments.user_id + size(arguments.tags)");
        assert_eq!(got, vec!["user_id".to_owned(), "tags".to_owned()]);
        assert!(extract_argument_idents("1 + 2").is_empty());
    }

    #[tokio::test]
    async fn output_schema_is_object() {
        let plugin = DuckDbBackendPlugin::new();
        let schema = BackendPlugin::output_schema(&plugin, "an").unwrap();
        assert_eq!(schema["type"], json!("object"));
    }

    #[tokio::test]
    async fn input_schema_lists_referenced_params() {
        let plugin = DuckDbBackendPlugin::new();
        plugin
            .register_profile("an", &minimal_spec(), no_op_host())
            .await
            .expect("register");
        let schema = BackendPlugin::input_schema(&plugin, "an").unwrap();
        assert_eq!(schema["type"], json!("object"));
        assert_eq!(schema["additionalProperties"], json!(true));
        assert!(schema["properties"]["id"].is_object());
    }

    #[tokio::test]
    async fn register_accepts_minimal_spec() {
        let plugin = DuckDbBackendPlugin::new();
        plugin
            .register_profile("an", &minimal_spec(), no_op_host())
            .await
            .expect("register");
        let profiles = plugin.profiles.read().await;
        let p = profiles.get("an").unwrap();
        assert_eq!(p.database, ":memory:");
        assert!(p.read_only);
        assert!(!p.allow_external_access);
        assert_eq!(p.compiled_params.len(), 1);
        // `:memory:` is never pooled — each call opens a fresh ephemeral engine.
        assert!(p.pool.is_none(), ":memory: must not be pooled");
    }

    #[tokio::test]
    async fn register_rejects_zero_pool_max_size() {
        let plugin = DuckDbBackendPlugin::new();
        let mut spec = minimal_spec();
        spec["pool_max_size"] = json!(0);
        let err = plugin
            .register_profile("x", &spec, no_op_host())
            .await
            .expect_err("zero pool_max_size");
        assert!(matches!(err, BackendError::InvalidSpec { .. }));
    }

    /// A FILE database registers a LAZY pool — built at register time with the
    /// configured capacity, but holding no connection (no file opened) until the
    /// first call.
    #[tokio::test]
    async fn register_builds_lazy_pool_for_file_db() {
        let dir = tempfile::tempdir().expect("tempdir");
        let db = dir.path().join("lazy.duckdb");
        let plugin = DuckDbBackendPlugin::new();
        let spec = json!({
            "database": db.display().to_string(),
            "read_only": false,
            "statement": "SELECT 1 AS one",
            "pool_max_size": 3,
        });
        plugin
            .register_profile("f", &spec, no_op_host())
            .await
            .expect("register file db");
        let profiles = plugin.profiles.read().await;
        let p = profiles.get("f").unwrap();
        let pool = p.pool.as_ref().expect("file db must be pooled");
        assert_eq!(pool.status().max_size, 3);
        assert_eq!(pool.status().size, 0, "lazy pool must hold no connection");
        // No file was opened at register — the DuckDB file does not yet exist.
        assert!(!db.exists(), "register must not open the file (stay lazy)");
    }

    /// Two calls against a pooled FILE database both succeed and return correct
    /// rows — proving the pooled connection is reused and the guards / init_sql
    /// hold across calls.
    #[tokio::test]
    async fn pooled_file_db_reuses_connection_across_calls() {
        let dir = tempfile::tempdir().expect("tempdir");
        let db = dir.path().join("pooled.duckdb");
        let db_path = db.display().to_string();
        let plugin = DuckDbBackendPlugin::new();

        // Seed the file (read_only=false): init_sql creates + populates a table.
        let seed = json!({
            "database": db_path,
            "read_only": false,
            "init_sql": ["CREATE TABLE IF NOT EXISTS t(id INTEGER, label TEXT)"],
            "statement": "INSERT INTO t VALUES (1, 'a'), (2, 'b')",
        });
        plugin
            .register_profile("seed", &seed, no_op_host())
            .await
            .expect("register seed");
        let env = exec(&plugin, "seed", json!({})).await;
        assert!(env["downstreamError"].is_null(), "seed errored: {env}");

        // Read it back twice through a pooled read-only profile (pool_max_size=2).
        let getp = json!({
            "database": db_path,
            "read_only": true,
            "statement": "SELECT id, label FROM t WHERE id = ?",
            "params": ["arguments.id"],
            "pool_max_size": 2,
        });
        plugin
            .register_profile("get", &getp, no_op_host())
            .await
            .expect("register get");

        let env1 = exec(&plugin, "get", json!({ "id": 1 })).await;
        assert!(env1["downstreamError"].is_null(), "call 1 errored: {env1}");
        assert_eq!(env1["response"]["count"], json!(1), "{env1}");
        assert_eq!(env1["response"]["rows"][0]["label"], json!("a"));

        let env2 = exec(&plugin, "get", json!({ "id": 2 })).await;
        assert!(env2["downstreamError"].is_null(), "call 2 errored: {env2}");
        assert_eq!(env2["response"]["count"], json!(1), "{env2}");
        assert_eq!(env2["response"]["rows"][0]["label"], json!("b"));

        // The pool has materialised at least one connection now (reused, not
        // re-opened per call). The read-only open-mode guard held: the SELECT
        // succeeded against the read-only handle.
        let profiles = plugin.profiles.read().await;
        let pool = profiles.get("get").unwrap().pool.as_ref().unwrap();
        assert!(
            pool.status().size >= 1,
            "pool should hold a live connection"
        );
    }

    /// `:memory:` stays per-call ephemeral even after pooling was added for file
    /// DBs: a row written in one call is NOT visible in the next, because each
    /// call gets a fresh engine.
    #[tokio::test]
    async fn memory_db_is_per_call_ephemeral() {
        let plugin = DuckDbBackendPlugin::new();
        // A write profile (read_only=false) that creates + inserts into a temp
        // table, returning a read-only count via a CTE-style SELECT.
        let create = json!({
            "database": ":memory:",
            "read_only": false,
            "statement": "CREATE TABLE seen(x INTEGER)",
        });
        plugin
            .register_profile("create", &create, no_op_host())
            .await
            .expect("register create");
        let env = exec(&plugin, "create", json!({})).await;
        assert!(env["downstreamError"].is_null(), "create errored: {env}");

        // A separate read profile: the table from the previous call must NOT
        // exist, because `:memory:` opened a brand-new engine for this call.
        let read = json!({
            "database": ":memory:",
            "statement": "SELECT count(*) AS n FROM seen",
        });
        plugin
            .register_profile("read", &read, no_op_host())
            .await
            .expect("register read");
        let env = exec(&plugin, "read", json!({})).await;
        assert!(
            !env["downstreamError"].is_null(),
            "ephemeral :memory: must not see the prior call's table: {env}"
        );
    }

    #[tokio::test]
    async fn register_rejects_non_select_when_read_only() {
        let plugin = DuckDbBackendPlugin::new();
        let mut spec = minimal_spec();
        spec["statement"] = json!("DELETE FROM t");
        let err = plugin
            .register_profile("x", &spec, no_op_host())
            .await
            .expect_err("non-select under read_only");
        assert!(matches!(err, BackendError::InvalidSpec { .. }));
    }

    #[tokio::test]
    async fn register_allows_non_select_when_not_read_only() {
        let plugin = DuckDbBackendPlugin::new();
        let mut spec = minimal_spec();
        spec["read_only"] = json!(false);
        spec["statement"] = json!("CREATE TABLE t(x INTEGER)");
        spec["params"] = json!([]);
        plugin
            .register_profile("w", &spec, no_op_host())
            .await
            .expect("write under read_only=false");
    }

    #[tokio::test]
    async fn register_rejects_bad_attach_alias() {
        let plugin = DuckDbBackendPlugin::new();
        let mut spec = minimal_spec();
        spec["allow_external_access"] = json!(true);
        spec["attach"] = json!([{ "alias": "bad;DROP", "source": "x.db" }]);
        let err = plugin
            .register_profile("x", &spec, no_op_host())
            .await
            .expect_err("bad alias");
        assert!(matches!(err, BackendError::InvalidSpec { .. }));
    }

    #[tokio::test]
    async fn register_rejects_bare_cred() {
        let plugin = DuckDbBackendPlugin::new();
        let mut spec = minimal_spec();
        spec["init_sql"] = json!(["CREATE SECRET s (KEY_ID 'cred://aws/x#id')"]);
        let err = plugin
            .register_profile("x", &spec, no_op_host())
            .await
            .expect_err("bare cred");
        assert!(matches!(err, BackendError::InvalidSpec { .. }));
    }

    #[tokio::test]
    async fn register_rejects_empty_statement() {
        let plugin = DuckDbBackendPlugin::new();
        let mut spec = minimal_spec();
        spec["statement"] = json!("   ");
        let err = plugin
            .register_profile("x", &spec, no_op_host())
            .await
            .expect_err("empty statement");
        assert!(matches!(err, BackendError::InvalidSpec { .. }));
    }

    #[tokio::test]
    async fn execute_unknown_profile_is_profile_not_found() {
        let plugin = DuckDbBackendPlugin::new();
        let req = BackendRequest {
            payload: vec![],
            headers: vec![],
            request_id: "rq-1".into(),
            session_id: None,
            identity: None,
            idempotency: None,
        };
        let err = plugin.execute("missing", req).await.expect_err("missing");
        assert!(matches!(err, BackendError::ProfileNotFound { .. }));
    }

    /// End-to-end against the real embedded engine: register a `:memory:`
    /// profile, call it with a bound parameter, and assert the JSON rows.
    #[tokio::test]
    async fn execute_runs_against_real_memory_engine() {
        let plugin = DuckDbBackendPlugin::new();
        let spec = json!({
            "database": ":memory:",
            "statement": "SELECT i AS id, i * 10 AS tens FROM range(5) AS t(i) WHERE i >= ?",
            "params": ["arguments.min"],
        });
        plugin
            .register_profile("q", &spec, no_op_host())
            .await
            .expect("register");

        let req = BackendRequest {
            payload: serde_json::to_vec(&json!({ "min": 3 })).unwrap(),
            headers: vec![("mcpg-tool-name".into(), "q".into())],
            request_id: "rq-2".into(),
            session_id: None,
            identity: None,
            idempotency: None,
        };
        let resp = plugin.execute("q", req).await.expect("execute");
        let env: Value = serde_json::from_slice(&resp.payload).expect("envelope json");
        assert!(env["downstreamError"].is_null(), "errored: {env}");
        assert_eq!(env["response"]["count"], json!(2));
        assert_eq!(env["response"]["rows"][0]["id"], json!(3));
        assert_eq!(env["response"]["rows"][0]["tens"], json!(30));
        assert_eq!(env["response"]["rows"][1]["id"], json!(4));
    }

    #[tokio::test]
    async fn register_rejects_uri_on_tool_surface() {
        let plugin = DuckDbBackendPlugin::new();
        let mut spec = json!({
            "database": ":memory:",
            "statement": "SELECT 1 AS one",
            "uri": "duckdb://x",
        });
        spec["surface"] = json!("tool");
        let err = plugin
            .register_profile("x", &spec, no_op_host())
            .await
            .expect_err("uri on tool surface");
        assert!(matches!(err, BackendError::InvalidSpec { .. }));
    }

    #[tokio::test]
    async fn resource_surface_emits_contents_body() {
        let plugin = DuckDbBackendPlugin::new();
        let spec = json!({
            "database": ":memory:",
            "statement": "SELECT i AS id FROM range(2) AS t(i)",
            "surface": "resource",
        });
        plugin
            .register_profile("r", &spec, no_op_host())
            .await
            .expect("register");
        let req = BackendRequest {
            payload: serde_json::to_vec(&json!({ "uri": "duckdb://docs/all" })).unwrap(),
            headers: vec![("mcpg-tool-name".into(), "r".into())],
            request_id: "rq-r".into(),
            session_id: None,
            identity: None,
            idempotency: None,
        };
        let resp = plugin.execute("r", req).await.expect("execute");
        let body: Value = serde_json::from_slice(&resp.payload).expect("body json");
        let contents = body["contents"].as_array().expect("contents array");
        assert_eq!(contents.len(), 1);
        assert_eq!(contents[0]["uri"], json!("duckdb://docs/all"));
        assert!(contents[0]["text"].is_string());
        assert!(contents[0].get("blob").is_none());
        assert_eq!(contents[0]["mimeType"], json!("application/json"));
    }

    #[tokio::test]
    async fn resource_surface_without_uri_yields_error_envelope() {
        let plugin = DuckDbBackendPlugin::new();
        let spec = json!({
            "database": ":memory:",
            "statement": "SELECT 1 AS one",
            "surface": "resource",
        });
        plugin
            .register_profile("r", &spec, no_op_host())
            .await
            .expect("register");
        let req = BackendRequest {
            payload: serde_json::to_vec(&json!({})).unwrap(),
            headers: vec![("mcpg-tool-name".into(), "r".into())],
            request_id: "rq-r2".into(),
            session_id: None,
            identity: None,
            idempotency: None,
        };
        let resp = plugin.execute("r", req).await.expect("execute");
        let body: Value = serde_json::from_slice(&resp.payload).expect("body json");
        assert!(body.get("contents").is_none());
        assert!(!body["downstreamError"].is_null());
    }

    #[tokio::test]
    async fn prompt_surface_emits_messages_body() {
        let plugin = DuckDbBackendPlugin::new();
        let spec = json!({
            "database": ":memory:",
            "statement": "SELECT i AS id FROM range(1) AS t(i)",
            "surface": "prompt",
        });
        plugin
            .register_profile("p", &spec, no_op_host())
            .await
            .expect("register");
        let req = BackendRequest {
            payload: serde_json::to_vec(&json!({})).unwrap(),
            headers: vec![("mcpg-tool-name".into(), "p".into())],
            request_id: "rq-p".into(),
            session_id: None,
            identity: None,
            idempotency: None,
        };
        let resp = plugin.execute("p", req).await.expect("execute");
        let body: Value = serde_json::from_slice(&resp.payload).expect("body json");
        let messages = body["messages"].as_array().expect("messages array");
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0]["role"], json!("user"));
        assert_eq!(messages[0]["content"]["type"], json!("text"));
        assert!(messages[0]["content"]["text"].is_string());
    }

    #[tokio::test]
    async fn tool_surface_unchanged_envelope() {
        let plugin = DuckDbBackendPlugin::new();
        let spec = json!({
            "database": ":memory:",
            "statement": "SELECT 1 AS one",
        });
        plugin
            .register_profile("t", &spec, no_op_host())
            .await
            .expect("register");
        let req = BackendRequest {
            payload: serde_json::to_vec(&json!({})).unwrap(),
            headers: vec![("mcpg-tool-name".into(), "t".into())],
            request_id: "rq-t".into(),
            session_id: None,
            identity: None,
            idempotency: None,
        };
        let resp = plugin.execute("t", req).await.expect("execute");
        let env: Value = serde_json::from_slice(&resp.payload).expect("body json");
        assert!(env.get("contents").is_none());
        assert!(env.get("messages").is_none());
        assert_eq!(env["response"]["rows"][0]["one"], json!(1));
    }

    #[tokio::test]
    async fn list_resources_empty_when_unconfigured() {
        let plugin = DuckDbBackendPlugin::new();
        plugin
            .register_profile("q", &minimal_spec(), no_op_host())
            .await
            .expect("register");
        let page = BackendPlugin::list_resources(&plugin, "q", None)
            .await
            .expect("list");
        assert!(page.resources.is_empty());
        assert!(page.next_cursor.is_none());
    }

    #[tokio::test]
    async fn list_resources_maps_rows_against_real_engine() {
        let plugin = DuckDbBackendPlugin::new();
        // Keyset cursor is bound as a single `?` (NULL on the first page);
        // COALESCE turns the NULL first-page cursor into a sentinel lower bound.
        let spec = json!({
            "database": ":memory:",
            "statement": "SELECT 1 AS one",
            "surface": "resource",
            "list_query": {
                "sql": "SELECT 'duckdb://item/' || i AS uri, 'Item ' || i AS name, i AS id \
                        FROM range(5) AS t(i) WHERE i > COALESCE(CAST(? AS BIGINT), -1) \
                        ORDER BY i LIMIT ?",
                "cursor_column": "id",
                "page_size": 2,
            },
        });
        plugin
            .register_profile("r", &spec, no_op_host())
            .await
            .expect("register");

        // First page (no cursor): items 0,1; full page → next_cursor = "1".
        let page = BackendPlugin::list_resources(&plugin, "r", None)
            .await
            .expect("list page 1");
        assert_eq!(page.resources.len(), 2);
        assert_eq!(page.resources[0].uri, "duckdb://item/0");
        assert_eq!(page.resources[0].name.as_deref(), Some("Item 0"));
        assert_eq!(page.next_cursor.as_deref(), Some("1"));

        // Second page: items 2,3.
        let page2 = BackendPlugin::list_resources(&plugin, "r", page.next_cursor.as_deref())
            .await
            .expect("list page 2");
        assert_eq!(page2.resources.len(), 2);
        assert_eq!(page2.resources[0].uri, "duckdb://item/2");
        assert_eq!(page2.next_cursor.as_deref(), Some("3"));

        // Last page: item 4 only → short page → exhausted.
        let page3 = BackendPlugin::list_resources(&plugin, "r", page2.next_cursor.as_deref())
            .await
            .expect("list page 3");
        assert_eq!(page3.resources.len(), 1);
        assert_eq!(page3.resources[0].uri, "duckdb://item/4");
        assert!(page3.next_cursor.is_none());
    }

    #[tokio::test]
    async fn complete_template_variable_returns_prefix_matches() {
        let plugin = DuckDbBackendPlugin::new();
        let spec = json!({
            "database": ":memory:",
            "statement": "SELECT 1 AS one",
            "surface": "resource",
            "variable_completions": {
                "name": {
                    "sql": "SELECT name FROM (VALUES ('alpha'), ('alphabet'), ('beta')) AS t(name) \
                            WHERE name LIKE ? || '%' ORDER BY name",
                    "max_results": 10,
                },
            },
        });
        plugin
            .register_profile("c", &spec, no_op_host())
            .await
            .expect("register");

        let got = BackendPlugin::complete_template_variable(
            &plugin,
            "c",
            "name",
            "alph",
            &json!({}),
            &BTreeMap::new(),
        )
        .await
        .expect("complete");
        assert_eq!(got, vec!["alpha".to_owned(), "alphabet".to_owned()]);

        // Unconfigured variable → empty.
        let none = BackendPlugin::complete_template_variable(
            &plugin,
            "c",
            "other",
            "x",
            &json!({}),
            &BTreeMap::new(),
        )
        .await
        .expect("complete other");
        assert!(none.is_empty());
    }

    #[tokio::test]
    async fn complete_template_variable_empty_when_unconfigured() {
        let plugin = DuckDbBackendPlugin::new();
        plugin
            .register_profile("q", &minimal_spec(), no_op_host())
            .await
            .expect("register");
        let got = BackendPlugin::complete_template_variable(
            &plugin,
            "q",
            "v",
            "x",
            &json!({}),
            &BTreeMap::new(),
        )
        .await
        .expect("complete");
        assert!(got.is_empty());
    }

    // ---------------------------------------------------------- introspection

    #[tokio::test]
    async fn register_list_tables_needs_no_statement() {
        let plugin = DuckDbBackendPlugin::new();
        let spec = json!({
            "database": ":memory:",
            "operation": "list_tables",
        });
        plugin
            .register_profile("lt", &spec, no_op_host())
            .await
            .expect("list_tables needs no statement");
        let profiles = plugin.profiles.read().await;
        assert_eq!(
            profiles.get("lt").unwrap().operation,
            DuckDbOperation::ListTables
        );
    }

    #[tokio::test]
    async fn register_list_columns_requires_table() {
        let plugin = DuckDbBackendPlugin::new();
        let no_table = json!({ "database": ":memory:", "operation": "list_columns" });
        let err = plugin
            .register_profile("lc", &no_table, no_op_host())
            .await
            .expect_err("list_columns needs a table");
        assert!(matches!(err, BackendError::InvalidSpec { .. }));

        let with_arg = json!({
            "database": ":memory:",
            "operation": "list_columns",
            "catalog_filters": { "table_arg": "t" },
        });
        plugin
            .register_profile("lc2", &with_arg, no_op_host())
            .await
            .expect("table_arg satisfies list_columns");
    }

    /// The read-only keyword guard must not run for the catalog ops (no
    /// statement) — and the introspection output is typed.
    #[tokio::test]
    async fn list_tables_output_schema_is_typed() {
        let plugin = DuckDbBackendPlugin::new();
        plugin
            .register_profile(
                "lt",
                &json!({ "database": ":memory:", "operation": "list_tables" }),
                no_op_host(),
            )
            .await
            .expect("register");
        let schema = BackendPlugin::output_schema(&plugin, "lt").unwrap();
        let items = &schema["properties"]["response"]["properties"]["rows"]["items"];
        assert!(items["properties"]["table_name"].is_object());
    }

    /// `list_columns` catalog args surface in the input schema; `read_file` and
    /// `query` use the CEL-referenced names instead.
    #[tokio::test]
    async fn list_columns_input_schema_lists_filter_args() {
        let plugin = DuckDbBackendPlugin::new();
        let spec = json!({
            "database": ":memory:",
            "operation": "list_columns",
            "catalog_filters": { "table_arg": "tbl", "schema_arg": "sch" },
        });
        plugin
            .register_profile("lc", &spec, no_op_host())
            .await
            .expect("register");
        let schema = BackendPlugin::input_schema(&plugin, "lc").unwrap();
        assert!(schema["properties"]["tbl"].is_object());
        assert!(schema["properties"]["sch"].is_object());
    }

    /// End-to-end introspection against the real engine: seed two tables in a
    /// file DB (so the schema survives across calls), then `list_tables` and
    /// `list_columns` over them.
    #[tokio::test]
    async fn list_tables_and_columns_against_real_engine() {
        let dir = tempfile::tempdir().expect("tempdir");
        let db = dir.path().join("schema.duckdb");
        let db_path = db.display().to_string();
        let plugin = DuckDbBackendPlugin::new();

        let seed = json!({
            "database": db_path,
            "read_only": false,
            "statement": "CREATE TABLE customers(id INTEGER, name TEXT)",
        });
        plugin
            .register_profile("seed", &seed, no_op_host())
            .await
            .expect("seed");
        let env = exec(&plugin, "seed", json!({})).await;
        assert!(env["downstreamError"].is_null(), "seed errored: {env}");

        // list_tables filtered to schema=main (bound as a param).
        let lt = json!({
            "database": db_path,
            "operation": "list_tables",
            "catalog_filters": { "schema": "main" },
        });
        plugin
            .register_profile("lt", &lt, no_op_host())
            .await
            .expect("lt");
        let env = exec(&plugin, "lt", json!({})).await;
        assert!(
            env["downstreamError"].is_null(),
            "list_tables errored: {env}"
        );
        let rows = env["response"]["rows"].as_array().expect("rows");
        assert!(rows.iter().any(|r| r["table_name"] == json!("customers")));

        // list_columns scoped to the customers table (static filter).
        let lc = json!({
            "database": db_path,
            "operation": "list_columns",
            "catalog_filters": { "table": "customers" },
        });
        plugin
            .register_profile("lc", &lc, no_op_host())
            .await
            .expect("lc");
        let env = exec(&plugin, "lc", json!({})).await;
        assert!(
            env["downstreamError"].is_null(),
            "list_columns errored: {env}"
        );
        let cols: Vec<&str> = env["response"]["rows"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|r| r["column_name"].as_str())
            .collect();
        assert_eq!(cols, vec!["id", "name"]);
    }

    /// A per-call `table_arg` narrows `list_columns` to the caller-named table —
    /// bound as a param, never interpolated.
    #[tokio::test]
    async fn list_columns_table_arg_binds_caller_value() {
        let dir = tempfile::tempdir().expect("tempdir");
        let db = dir.path().join("two.duckdb");
        let db_path = db.display().to_string();
        let plugin = DuckDbBackendPlugin::new();
        let seed = json!({
            "database": db_path,
            "read_only": false,
            "statement": "CREATE TABLE a(x INTEGER); CREATE TABLE b(y TEXT, z TEXT)",
        });
        plugin
            .register_profile("seed", &seed, no_op_host())
            .await
            .expect("seed");
        let _ = exec(&plugin, "seed", json!({})).await;

        let lc = json!({
            "database": db_path,
            "operation": "list_columns",
            "catalog_filters": { "table_arg": "table" },
        });
        plugin
            .register_profile("lc", &lc, no_op_host())
            .await
            .expect("lc");

        let env = exec(&plugin, "lc", json!({ "table": "b" })).await;
        assert!(env["downstreamError"].is_null(), "errored: {env}");
        let cols: Vec<&str> = env["response"]["rows"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|r| r["column_name"].as_str())
            .collect();
        assert_eq!(cols, vec!["y", "z"]);
    }

    // -------------------------------------------------------------- read_file

    #[tokio::test]
    async fn register_read_file_requires_external_access() {
        let plugin = DuckDbBackendPlugin::new();
        let spec = json!({
            "database": ":memory:",
            "operation": "read_file",
            "read_file": { "path": "/data/x.parquet" },
            // allow_external_access defaults to false → must be rejected.
        });
        let err = plugin
            .register_profile("rf", &spec, no_op_host())
            .await
            .expect_err("read_file needs external access");
        assert!(matches!(err, BackendError::InvalidSpec { .. }));
        assert!(err.to_string().contains("allow_external_access"));
    }

    #[tokio::test]
    async fn register_read_file_requires_config_block() {
        let plugin = DuckDbBackendPlugin::new();
        let spec = json!({
            "database": ":memory:",
            "operation": "read_file",
            "allow_external_access": true,
        });
        let err = plugin
            .register_profile("rf", &spec, no_op_host())
            .await
            .expect_err("read_file needs config");
        assert!(matches!(err, BackendError::InvalidSpec { .. }));
    }

    /// The read_file path is OPERATOR-CONFIG ONLY: the binding exposes no path
    /// argument, so a caller-supplied `path` in the call arguments is ignored —
    /// the read still targets the operator-fixed file. This is the LFI/SSRF
    /// guard: a caller can never redirect the read at an arbitrary file.
    #[tokio::test]
    async fn read_file_ignores_caller_supplied_path() {
        let dir = tempfile::tempdir().expect("tempdir");
        let allowed = dir.path().join("allowed.csv");
        std::fs::write(&allowed, "region,amount\nemea,100\n").unwrap();
        let secret = dir.path().join("secret.csv");
        std::fs::write(&secret, "region,amount\nleaked,999\n").unwrap();

        let plugin = DuckDbBackendPlugin::new();
        let spec = json!({
            "database": ":memory:",
            "operation": "read_file",
            "allow_external_access": true,
            "read_file": { "path": allowed.display().to_string(), "format": "csv" },
        });
        plugin
            .register_profile("rf", &spec, no_op_host())
            .await
            .expect("register");

        // A malicious caller tries to redirect at the secret file — the arg is
        // not wired to anything, so the operator-fixed path is read instead.
        let env = exec(
            &plugin,
            "rf",
            json!({ "path": secret.display().to_string() }),
        )
        .await;
        assert!(env["downstreamError"].is_null(), "errored: {env}");
        let rows = env["response"]["rows"].as_array().expect("rows");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["region"], json!("emea"));
        assert_ne!(rows[0]["region"], json!("leaked"));
    }

    /// The operator-fixed `predicate` `?` binds from the CEL `params` against the
    /// caller arguments — injection-safe filtering of an external file read.
    #[tokio::test]
    async fn read_file_predicate_binds_caller_param() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("sales.csv");
        std::fs::write(&path, "region,amount\nemea,100\napac,5\nus,300\n").unwrap();

        let plugin = DuckDbBackendPlugin::new();
        let spec = json!({
            "database": ":memory:",
            "operation": "read_file",
            "allow_external_access": true,
            "read_file": {
                "path": path.display().to_string(),
                "format": "csv",
                "columns": ["region", "amount"],
                "predicate": "amount >= ?",
            },
            "params": ["arguments.min"],
        });
        plugin
            .register_profile("rf", &spec, no_op_host())
            .await
            .expect("register");

        let env = exec(&plugin, "rf", json!({ "min": 100 })).await;
        assert!(env["downstreamError"].is_null(), "errored: {env}");
        let regions: Vec<&str> = env["response"]["rows"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|r| r["region"].as_str())
            .collect();
        assert_eq!(regions, vec!["emea", "us"]);
    }

    #[tokio::test]
    async fn register_rejects_keyset_list_query_without_cursor() {
        let plugin = DuckDbBackendPlugin::new();
        let mut spec = minimal_spec();
        spec["surface"] = json!("resource");
        spec["list_query"] = json!({ "sql": "SELECT id AS uri FROM t" });
        let err = plugin
            .register_profile("x", &spec, no_op_host())
            .await
            .expect_err("missing cursor_column");
        assert!(matches!(err, BackendError::InvalidSpec { .. }));
    }

    // ------------------------------------------------- resource_template read

    /// A resource_template binding may declare a per-`{id}` `read_query` and omit
    /// `statement`; the profile stores it and stays read-only-guarded.
    #[tokio::test]
    async fn register_resource_template_read_query() {
        let plugin = DuckDbBackendPlugin::new();
        let spec = json!({
            "database": ":memory:",
            "surface": "resource",
            "read_query": "SELECT * FROM orders WHERE id = ?",
            "params": ["arguments.id"],
        });
        plugin
            .register_profile("rt", &spec, no_op_host())
            .await
            .expect("read_query registers without a statement");
        let profiles = plugin.profiles.read().await;
        let p = profiles.get("rt").unwrap();
        assert_eq!(
            p.read_query.as_deref(),
            Some("SELECT * FROM orders WHERE id = ?")
        );
        assert!(p.statement.is_empty());
        assert_eq!(p.surface, surface::Surface::Resource);
        assert_eq!(p.compiled_params.len(), 1);
    }

    #[tokio::test]
    async fn register_rejects_read_query_on_tool_surface() {
        let plugin = DuckDbBackendPlugin::new();
        let mut spec = minimal_spec();
        spec["read_query"] = json!("SELECT * FROM t WHERE id = ?");
        let err = plugin
            .register_profile("x", &spec, no_op_host())
            .await
            .expect_err("read_query on tool surface");
        match err {
            BackendError::InvalidSpec { message } => {
                assert!(message.contains("read_query"), "{message}");
                assert!(message.contains("surface: resource"), "{message}");
            }
            other => panic!("expected InvalidSpec, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn register_rejects_non_read_only_read_query() {
        let plugin = DuckDbBackendPlugin::new();
        let spec = json!({
            "database": ":memory:",
            "surface": "resource",
            "read_query": "DELETE FROM orders WHERE id = ?",
            "params": ["arguments.id"],
        });
        let err = plugin
            .register_profile("x", &spec, no_op_host())
            .await
            .expect_err("non-read-only read_query");
        assert!(matches!(err, BackendError::InvalidSpec { .. }));
    }

    #[tokio::test]
    async fn register_rejects_bare_cred_read_query() {
        let plugin = DuckDbBackendPlugin::new();
        let spec = json!({
            "database": ":memory:",
            "surface": "resource",
            "read_query": "SELECT * FROM t WHERE k = 'cred://aws/x#id'",
            "params": [],
        });
        let err = plugin
            .register_profile("x", &spec, no_op_host())
            .await
            .expect_err("bare cred in read_query");
        assert!(matches!(err, BackendError::InvalidSpec { .. }));
    }

    /// The gateway delivers the extracted template variable as `arguments.<var>`;
    /// the binding's `params` CEL bind it to the `read_query`'s `?` placeholder.
    /// A value crafted to look like SQL is carried verbatim as a single scalar
    /// bind (a `DuckBind::Str`) — it is data for the driver to escape, never
    /// spliced into the statement text.
    #[test]
    fn template_var_binds_as_param_not_interpolated() {
        let compiled = params::compile_params(&["arguments.id".to_owned()]).unwrap();
        // What the gateway hands the backend for `duckdb://orders/{id}` on a read
        // of `duckdb://orders/1 OR 1=1; DROP TABLE orders`.
        let injection = "1 OR 1=1; DROP TABLE orders";
        let args = json!({
            "uri": format!("duckdb://orders/{injection}"),
            "id": injection,
            "template_vars": { "id": injection },
        });
        let values = params::evaluate_params(&compiled, &args).unwrap();
        assert_eq!(values, vec![json!(injection)]);
        let bind = params::json_to_duck_bind(values.into_iter().next().unwrap()).unwrap();
        // The whole injection string is one opaque scalar bind — the driver
        // escapes it as a SQL string literal; it never reaches SQL as text.
        assert_eq!(bind, params::DuckBind::Str(injection.to_owned()));
    }

    /// The resource-read branch shapes a single fabricated row into the
    /// `resources/read` contract body keyed on the concrete (gateway-supplied)
    /// URI.
    #[test]
    fn resource_template_read_shapes_single_row_contents() {
        let uri = "duckdb://orders/42";
        let row = json!({ "id": 42, "total": 19.99 });
        let body = surface::resource_contents_body(uri, std::slice::from_ref(&row));
        let contents = body["contents"].as_array().expect("contents");
        assert_eq!(contents.len(), 1);
        assert_eq!(contents[0]["uri"], json!(uri));
        assert_eq!(contents[0]["mimeType"], json!("application/json"));
        let decoded: Vec<Value> =
            serde_json::from_str(contents[0]["text"].as_str().unwrap()).unwrap();
        assert_eq!(decoded, vec![row]);
    }

    /// End-to-end against the real embedded engine: a `read_query` binding reads a
    /// single row for the gateway-extracted `{id}` (bound, not interpolated) and
    /// shapes it into the `resources/read` `{contents}` body keyed on the
    /// concrete URI. An injection-shaped `{id}` binds opaquely and matches no row.
    #[tokio::test]
    async fn read_query_single_row_read_against_real_engine() {
        let plugin = DuckDbBackendPlugin::new();
        // The default `query` op on the resource surface selects `read_query` over
        // `statement`; `range()` fabricates rows so no seeding is needed.
        let spec = json!({
            "database": ":memory:",
            "surface": "resource",
            "read_query": "SELECT i AS id, i * 10 AS tens FROM range(5) AS t(i) WHERE i = CAST(? AS BIGINT)",
            "params": ["arguments.id"],
        });
        plugin
            .register_profile("rt", &spec, no_op_host())
            .await
            .expect("register");

        // resources/read of `duckdb://nums/3`: the gateway pre-extracts {id} → arguments.id.
        let env = exec(&plugin, "rt", json!({ "uri": "duckdb://nums/3", "id": 3 })).await;
        let contents = env["contents"].as_array().expect("contents array");
        assert_eq!(contents.len(), 1);
        assert_eq!(contents[0]["uri"], json!("duckdb://nums/3"));
        assert_eq!(contents[0]["mimeType"], json!("application/json"));
        let rows: Vec<Value> = serde_json::from_str(contents[0]["text"].as_str().unwrap()).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["id"], json!(3));
        assert_eq!(rows[0]["tens"], json!(30));

        // An injection-shaped {id} binds as one opaque scalar — it never executes
        // as SQL. The string fails to CAST to BIGINT (a clean downstream error)
        // rather than splicing into the statement; either way no injected
        // statement runs. Accept an error envelope or an empty contents read.
        let env2 = exec(
            &plugin,
            "rt",
            json!({ "uri": "duckdb://nums/x", "id": "3; DROP TABLE foo" }),
        )
        .await;
        if let Some(text) = env2["contents"][0]["text"].as_str() {
            let rows2: Vec<Value> = serde_json::from_str(text).unwrap();
            assert!(rows2.is_empty(), "injection bind must match no row: {env2}");
        } else {
            assert!(
                !env2["downstreamError"].is_null(),
                "expected an empty read or a clean downstream error: {env2}"
            );
        }
    }

    struct NoOpHost;

    #[async_trait]
    impl BackendHost for NoOpHost {
        async fn invoke_tool(
            &self,
            _ctx: &mcpg_plugin_protocol::BackendInvocationContext,
            _tool_name: &str,
            _args: &serde_json::Value,
        ) -> Result<serde_json::Value, mcpg_plugin_protocol::BackendHostError> {
            Err(mcpg_plugin_protocol::BackendHostError::NotImplemented)
        }
    }
}
