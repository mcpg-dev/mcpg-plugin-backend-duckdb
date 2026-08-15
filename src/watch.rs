//! `watch_strategy` entity (`duckdb_poll`) — the POLLING change-watch path.
//!
//! DuckDB has no native change-push channel, so this strategy polls a cheap
//! read-only scalar "high-water" query (`SELECT max(updated_at) FROM events`,
//! `SELECT count(*) FROM …`, a monotonic sequence, …) on a cadence and signals
//! a change whenever that scalar advances. The poll thread, the cursor diff, the
//! stop signal and the opaque handle round-trip all live in the shared
//! [`mcpg_plugin_sdk::watch`] helper — this entity only supplies the per-tick
//! `poll` closure over its own connection.
//!
//! The DuckDB driver is fully synchronous (rusqlite-style) and `Connection` is
//! `Send` but `!Sync`. The helper's loop runs the closure on its own dedicated
//! OS thread, so each tick opens a short-lived guarded connection to the file
//! database, runs the tracking query directly (no tokio runtime needed), and
//! drops it. Open / query failures map to the closure's `Err(String)` — the
//! helper logs and retries on the next tick.
//!
//! DuckDB-specific guard: only a **file-backed** database can be watched. A
//! `:memory:` database (or an absent / empty path) opens a fresh empty engine
//! per call, so there is no external change source to observe — that spec is
//! rejected at watch-validate.

use std::time::Duration;

use mcpg_plugin_protocol::backend::WatchError;
use mcpg_plugin_protocol::{PluginManifest, firstparty_manifest};
use mcpg_plugin_sdk::HostHandle;
use mcpg_plugin_sdk::ffi::{SyncWatchStrategyPlugin, WatchHandleBox};
use mcpg_plugin_sdk::watch::{cancel_polling_watch, spawn_polling_watch};
use serde::Deserialize;
use serde_json::Value;

use crate::duckdb::{QueryOutcome, enforce_read_only, run_query_blocking};
use crate::types::DuckDbAttach;

pub const PLUGIN_ID: &str = "dev.mcpg.backend.duckdb";

/// The strategy discriminator this entity handles.
pub const WATCH_KIND: &str = "duckdb_poll";

/// Default poll cadence when `interval_ms` is omitted (1 minute).
fn default_interval_ms() -> u64 {
    60_000
}

/// Default per-tick query budget when `timeout_ms` is omitted (10 seconds).
fn default_timeout_ms() -> u64 {
    10_000
}

fn default_read_only() -> bool {
    true
}

/// Per-watch spec: the DuckDB connection fields needed to open the file database
/// (reusing the backend's connection shape — `database` path + the `read_only`
/// and `allow_external_access` engine guards + the operator `init_sql` / ATTACH
/// setup) plus the read-only scalar high-water `tracking_query` and the poll
/// cadence. The connection is carried per-watch (not at plugin level), so a
/// watcher is self-contained.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WatchSpec {
    /// The database file path. MUST be file-backed — `:memory:` (or an
    /// absent/empty path) has no external change source and is rejected.
    database: String,
    /// Open the engine read-only (default true; file DBs only). The tracking
    /// query is fenced read-only independently of this flag.
    #[serde(default = "default_read_only")]
    read_only: bool,
    /// Allow the engine to touch the filesystem / network beyond the database
    /// file (`read_csv` / `httpfs` / `ATTACH <file>`). Default FALSE.
    #[serde(default)]
    allow_external_access: bool,
    /// Operator SQL run once when each tick's connection is opened (before the
    /// tracking query), e.g. `INSTALL httpfs; LOAD httpfs;`.
    #[serde(default)]
    init_sql: Vec<String>,
    /// Operator ATTACH targets, applied after `init_sql`.
    #[serde(default)]
    attach: Vec<DuckDbAttach>,
    /// The read-only scalar high-water query whose first-row first-column value
    /// is the cursor (e.g. `SELECT max(updated_at) FROM events`). REQUIRED.
    tracking_query: String,
    /// Poll cadence in milliseconds (default 60000; floored by the SDK helper).
    #[serde(default = "default_interval_ms")]
    interval_ms: u64,
    /// Per-tick open + statement + read budget in milliseconds (default 10000).
    #[serde(default = "default_timeout_ms")]
    timeout_ms: u64,
}

/// `watch_strategy` entity. Stateless beyond its manifest — every watcher's
/// connection + tracking query arrive on the per-watch spec.
pub struct DuckDbWatchCdylib {
    manifest: PluginManifest,
}

impl DuckDbWatchCdylib {
    /// Infallible cdylib factory. `config_json` + host are ignored — the watch
    /// carries no plugin-level config (the connection + `tracking_query` arrive
    /// via the per-watch spec).
    pub fn from_host_config(_config_json: &str, _host: HostHandle) -> Self {
        Self {
            manifest: firstparty_manifest! {
                id: "dev.mcpg.backend.duckdb",
                name: "DuckDB Poll Watch Strategy",
                class: WatchStrategy,
            },
        }
    }
}

/// Extract the cursor scalar from a high-water query outcome: the first column
/// of the first row, stringified. `None` when the query returned zero rows (no
/// signal this tick), the first row has no columns, or the scalar is SQL NULL.
/// String values yield the bare string; everything else its JSON rendering, so
/// the cursor comparison is stable across ticks.
fn cursor_from_outcome(outcome: &QueryOutcome) -> Option<String> {
    let first = outcome.rows.first()?;
    let scalar = first.as_object()?.values().next()?;
    Some(match scalar {
        Value::String(s) => s.clone(),
        Value::Null => return None,
        other => other.to_string(),
    })
}

/// True for a database string that has no external change source: `:memory:`
/// (or its `:memory:?...` config-flag form) or an absent / empty path. Such a
/// database gets a fresh empty engine per connection, so polling it would never
/// observe a change.
fn is_memory_or_empty(database: &str) -> bool {
    let db = database.trim();
    db.is_empty() || db == ":memory:" || db.starts_with(":memory:")
}

impl SyncWatchStrategyPlugin for DuckDbWatchCdylib {
    fn manifest(&self) -> &PluginManifest {
        &self.manifest
    }

    fn kind(&self) -> &str {
        WATCH_KIND
    }

    fn watch(
        &self,
        resource_uri: &str,
        spec: &Value,
        emit_event: Box<dyn Fn(&str) + Send + Sync + 'static>,
    ) -> Result<WatchHandleBox, WatchError> {
        let parsed: WatchSpec =
            serde_json::from_value(spec.clone()).map_err(|e| WatchError::InvalidSpec {
                message: format!("invalid duckdb_poll watch spec: {e}"),
            })?;

        let invalid = |m: String| WatchError::InvalidSpec { message: m };
        // The key DuckDB-specific guard: a `:memory:` (or empty-path) database
        // opens a fresh empty engine per connection, so it has no external
        // change source — reject it rather than poll a database that can never
        // advance.
        if is_memory_or_empty(&parsed.database) {
            return Err(invalid(
                "duckdb_poll requires a file-backed database; :memory: has no external change source"
                    .into(),
            ));
        }
        if parsed.tracking_query.trim().is_empty() {
            return Err(invalid("tracking_query must not be empty".into()));
        }
        // The tracking query is read-only by contract — reuse the backend's
        // keyword guard so a polling watcher can never mutate the database.
        enforce_read_only(&parsed.tracking_query).map_err(invalid)?;

        let WatchSpec {
            database,
            read_only,
            allow_external_access,
            init_sql,
            attach,
            tracking_query,
            interval_ms,
            timeout_ms,
        } = parsed;
        // `timeout_ms` is accepted for spec parity with the other poll watchers,
        // but the DuckDB driver is synchronous with no mid-call cancel hook, so a
        // tick runs to completion; the poll-thread cadence bounds how often it
        // can be re-entered.
        let _ = timeout_ms;

        let poll = move || -> Result<Option<String>, String> {
            // The DuckDB driver is synchronous: open a guarded connection to the
            // file DB on this poll thread, run the tracking query (capped at one
            // row), and drop the connection. Each tick is self-contained.
            let outcome = run_query_blocking(
                &database,
                read_only,
                allow_external_access,
                &init_sql,
                &attach,
                &tracking_query,
                Vec::new(),
                1,
            )
            .map_err(|e| {
                mcpg_plugin_protocol::redact::redact_in_text(&format!("duckdb_poll tick: {e}"))
            })?;
            Ok(cursor_from_outcome(&outcome))
        };

        Ok(spawn_polling_watch(
            resource_uri,
            Duration::from_millis(interval_ms),
            emit_event,
            poll,
        ))
    }

    fn cancel(&self, watch_handle: WatchHandleBox) {
        cancel_polling_watch(watch_handle);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn stub_host() -> HostHandle {
        // SAFETY: `stub_host_ref` returns a process-static no-op host ref; the
        // factory ignores the host entirely.
        #[allow(unsafe_code)]
        unsafe {
            HostHandle::from_ffi(mcpg_plugin_sdk::testing::stub_host_ref())
        }
    }

    fn plugin() -> DuckDbWatchCdylib {
        DuckDbWatchCdylib::from_host_config("", stub_host())
    }

    fn emit_noop() -> Box<dyn Fn(&str) + Send + Sync + 'static> {
        Box::new(|_| {})
    }

    #[test]
    fn manifest_and_kind_are_correct() {
        use mcpg_plugin_protocol::PluginClass;
        let p = plugin();
        let m = SyncWatchStrategyPlugin::manifest(&p);
        assert_eq!(m.id, PLUGIN_ID);
        assert_eq!(m.plugin_class, PluginClass::WatchStrategy);
        assert_eq!(p.kind(), WATCH_KIND);
    }

    #[test]
    fn spec_parses_with_defaults() {
        let parsed: WatchSpec = serde_json::from_value(json!({
            "database": "/data/warehouse.duckdb",
            "tracking_query": "SELECT max(updated_at) FROM events",
        }))
        .unwrap();
        assert_eq!(parsed.interval_ms, 60_000);
        assert_eq!(parsed.timeout_ms, 10_000);
        assert!(parsed.read_only);
        assert!(!parsed.allow_external_access);
        assert!(parsed.init_sql.is_empty());
        assert!(parsed.attach.is_empty());
    }

    #[test]
    fn spec_parses_overrides() {
        let parsed: WatchSpec = serde_json::from_value(json!({
            "database": "/data/warehouse.duckdb",
            "read_only": false,
            "allow_external_access": true,
            "init_sql": ["INSTALL httpfs; LOAD httpfs;"],
            "attach": [{ "alias": "lake", "source": "s3://b/db.duckdb", "read_only": true }],
            "tracking_query": "SELECT count(*) FROM events",
            "interval_ms": 30_000,
            "timeout_ms": 5_000,
        }))
        .unwrap();
        assert!(!parsed.read_only);
        assert!(parsed.allow_external_access);
        assert_eq!(parsed.init_sql.len(), 1);
        assert_eq!(parsed.attach.len(), 1);
        assert_eq!(parsed.interval_ms, 30_000);
        assert_eq!(parsed.timeout_ms, 5_000);
    }

    #[test]
    fn unknown_field_is_invalid_spec() {
        let p = plugin();
        assert!(matches!(
            p.watch(
                "duckdb://events",
                &json!({
                    "database": "/data/w.duckdb",
                    "tracking_query": "SELECT 1",
                    "bogus": true,
                }),
                emit_noop(),
            ),
            Err(WatchError::InvalidSpec { .. })
        ));
    }

    #[test]
    fn memory_database_is_invalid_spec() {
        let p = plugin();
        for db in [":memory:", ":memory:?cache=shared", "", "   "] {
            assert!(
                matches!(
                    p.watch(
                        "duckdb://events",
                        &json!({
                            "database": db,
                            "tracking_query": "SELECT max(t) FROM e",
                        }),
                        emit_noop(),
                    ),
                    Err(WatchError::InvalidSpec { .. })
                ),
                "should reject non-file database: {db:?}"
            );
        }
    }

    #[test]
    fn empty_tracking_query_is_invalid_spec() {
        let p = plugin();
        assert!(matches!(
            p.watch(
                "duckdb://events",
                &json!({ "database": "/data/w.duckdb", "tracking_query": "   " }),
                emit_noop(),
            ),
            Err(WatchError::InvalidSpec { .. })
        ));
    }

    #[test]
    fn non_read_only_tracking_query_is_invalid_spec() {
        let p = plugin();
        assert!(matches!(
            p.watch(
                "duckdb://events",
                &json!({
                    "database": "/data/w.duckdb",
                    "tracking_query": "DELETE FROM events",
                }),
                emit_noop(),
            ),
            Err(WatchError::InvalidSpec { .. })
        ));
    }

    #[test]
    fn cursor_from_outcome_extracts_first_scalar() {
        let outcome = QueryOutcome {
            rows: vec![json!({ "max(updated_at)": "2026-06-23 10:00:00" })],
            truncated: false,
            row_count: 1,
        };
        assert_eq!(
            cursor_from_outcome(&outcome).as_deref(),
            Some("2026-06-23 10:00:00")
        );

        let outcome = QueryOutcome {
            rows: vec![json!({ "count_star()": 42 })],
            truncated: false,
            row_count: 1,
        };
        assert_eq!(cursor_from_outcome(&outcome).as_deref(), Some("42"));
    }

    #[test]
    fn cursor_from_outcome_none_on_zero_rows_or_null() {
        let empty = QueryOutcome {
            rows: vec![],
            truncated: false,
            row_count: 0,
        };
        assert_eq!(cursor_from_outcome(&empty), None);

        let null = QueryOutcome {
            rows: vec![json!({ "max(t)": Value::Null })],
            truncated: false,
            row_count: 1,
        };
        assert_eq!(cursor_from_outcome(&null), None);
    }
}
