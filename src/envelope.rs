//! DuckDB structured response envelope — the `BackendResponse.payload` the
//! gateway projects onto `tools/call`. A non-null `downstreamError` slot is the
//! gateway's `is_error` signal (same contract as the oracle/snowflake/http
//! backends).

use serde_json::{Value, json};

/// Build a downstream-error object for the envelope's `downstreamError` slot.
pub fn duckdb_downstream_error(kind: &str, message: &str, retryable: bool) -> Value {
    json!({
        "kind": kind,
        "code": format!("mcpg.downstream_duckdb.{kind}"),
        "message": message,
        "retryable": retryable,
        "retryClass": if retryable { "with_backoff" } else { "do_not_retry" },
        "suggestedAction": if retryable { "check_storage_and_retry" } else { "inspect_sql_error" },
    })
}

/// Classify a query error string. Transient I/O / lock / timeout failures are
/// retryable transport errors; parser / binder / catalog / permission
/// rejections are caller/config problems and are not.
pub fn classify_error(message: &str) -> Value {
    let lower = message.to_ascii_lowercase();
    // Non-retryable first: a parser/binder/catalog/permission error must not be
    // masked as transport just because its text mentions a file or "io".
    let non_retryable = lower.contains("parser error")
        || lower.contains("binder error")
        || lower.contains("catalog error")
        || lower.contains("syntax error")
        || lower.contains("permission")
        || lower.contains("not allowed")
        || lower.contains("read-only guard")
        || lower.contains("external access")
        || lower.contains("conversion error")
        || lower.contains("invalid input");
    let retryable = !non_retryable
        && (lower.contains("io error")
            || lower.contains("i/o error")
            || lower.contains("disk")
            || lower.contains("lock")
            || lower.contains("could not set lock")
            || lower.contains("timed out")
            || lower.contains("timeout")
            || lower.contains("connection")
            || lower.contains("interrupt"));
    let kind = if retryable {
        "transport_error"
    } else {
        "duckdb_error"
    };
    duckdb_downstream_error(kind, message, retryable)
}

/// JSON Schema (draft 2020-12) for the fixed envelope wrapper
/// [`build_result_envelope`] produces. Describes the stable top-level
/// shape; per-query `response.rows` items are intentionally left untyped
/// (`{}`) so any row shape validates.
pub fn result_envelope_schema() -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "properties": {
            "toolName": { "type": "string" },
            "profile": { "type": "string" },
            "request": {
                "type": "object",
                "properties": {
                    "database": { "type": "string" }
                },
                "additionalProperties": true
            },
            "response": {
                "type": ["object", "null"],
                "properties": {
                    "rows": { "type": ["array", "null"], "items": {} },
                    "count": { "type": ["integer", "null"] },
                    "truncated": { "type": "boolean" },
                    "durationMs": { "type": "integer" }
                },
                "additionalProperties": true
            },
            "downstreamError": { "type": ["object", "null"] },
            "downstreamErrors": { "type": "array", "items": {} },
            "error": { "type": ["string", "null"] }
        },
        "additionalProperties": true
    })
}

/// Envelope schema specialized for a catalog-introspection operation: the same
/// wrapper as [`result_envelope_schema`] but with `response.rows` items typed to
/// the known `information_schema` column set. The object stays open
/// (`additionalProperties: true`).
pub fn catalog_envelope_schema(columns: &[&str]) -> Value {
    let mut schema = result_envelope_schema();
    let mut props = serde_json::Map::new();
    for col in columns {
        props.insert(
            (*col).to_owned(),
            json!({ "type": ["string", "integer", "null"] }),
        );
    }
    schema["properties"]["response"]["properties"]["rows"]["items"] = json!({
        "type": "object",
        "properties": Value::Object(props),
        "additionalProperties": true,
    });
    schema
}

/// Columns a `list_tables` introspection result yields
/// (`information_schema.tables`).
pub const LIST_TABLES_COLUMNS: &[&str] =
    &["table_catalog", "table_schema", "table_name", "table_type"];

/// Columns a `list_columns` introspection result yields
/// (`information_schema.columns`).
pub const LIST_COLUMNS_COLUMNS: &[&str] = &[
    "table_name",
    "column_name",
    "data_type",
    "is_nullable",
    "ordinal_position",
];

/// Build the DuckDB structured-content envelope returned as the
/// `BackendResponse.payload`.
#[allow(clippy::too_many_arguments)]
pub fn build_result_envelope(
    tool_name: &str,
    profile_name: &str,
    database: &str,
    rows: Option<&[Value]>,
    row_count: Option<usize>,
    truncated: bool,
    duration_ms: u128,
    downstream_error: Option<&Value>,
    error: Option<&str>,
) -> Value {
    let response = if downstream_error.is_some() {
        Value::Null
    } else {
        json!({
            "rows": rows,
            "count": row_count.or_else(|| rows.map(<[Value]>::len)),
            "truncated": truncated,
            "durationMs": duration_ms,
        })
    };
    json!({
        "toolName": tool_name,
        "profile": profile_name,
        "request": {
            "database": database,
        },
        "response": response,
        "downstreamError": downstream_error,
        "downstreamErrors": downstream_error
            .map(|d| vec![d.clone()])
            .unwrap_or_default(),
        "error": error,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn io_failure_is_retryable_transport_error() {
        let e = classify_error("DuckDB query failed: IO Error: could not read file");
        assert_eq!(e["kind"], json!("transport_error"));
        assert_eq!(e["retryable"], json!(true));
    }

    #[test]
    fn lock_failure_is_retryable() {
        let e = classify_error("Could not set lock on file: held by another process");
        assert_eq!(e["kind"], json!("transport_error"));
        assert_eq!(e["retryable"], json!(true));
    }

    #[test]
    fn binder_error_is_not_retryable() {
        let e = classify_error("DuckDB query failed: Binder Error: column \"bogus\" not found");
        assert_eq!(e["kind"], json!("duckdb_error"));
        assert_eq!(e["retryable"], json!(false));
    }

    #[test]
    fn external_access_denial_is_not_retryable() {
        let e = classify_error(
            "Permission Error: File system LocalFileSystem has been disabled by external access",
        );
        assert_eq!(e["kind"], json!("duckdb_error"));
        assert_eq!(e["retryable"], json!(false));
    }

    #[test]
    fn query_envelope_has_rows_and_count() {
        let rows = vec![json!({ "id": 1 })];
        let env = build_result_envelope(
            "u.get",
            "u.get",
            ":memory:",
            Some(&rows),
            Some(1),
            false,
            7,
            None,
            None,
        );
        assert_eq!(env["response"]["count"], json!(1));
        assert_eq!(env["response"]["rows"][0]["id"], json!(1));
        assert_eq!(env["response"]["truncated"], json!(false));
        assert_eq!(env["request"]["database"], json!(":memory:"));
        assert!(env["downstreamError"].is_null());
    }

    #[test]
    fn truncated_flag_is_carried() {
        let rows = vec![json!({ "id": 1 })];
        let env = build_result_envelope(
            "u.get",
            "u.get",
            "/d.duckdb",
            Some(&rows),
            Some(1),
            true,
            3,
            None,
            None,
        );
        assert_eq!(env["response"]["truncated"], json!(true));
    }

    #[test]
    fn error_envelope_nulls_response() {
        let d = classify_error("DuckDB query failed: Catalog Error: Table does not exist");
        let env = build_result_envelope(
            "u.get",
            "u.get",
            ":memory:",
            None,
            None,
            false,
            2,
            Some(&d),
            Some("table missing"),
        );
        assert!(env["response"].is_null());
        assert_eq!(env["downstreamError"]["kind"], json!("duckdb_error"));
    }

    #[test]
    fn catalog_envelope_schema_types_known_columns() {
        let schema = catalog_envelope_schema(LIST_TABLES_COLUMNS);
        let items = &schema["properties"]["response"]["properties"]["rows"]["items"];
        assert_eq!(items["type"], json!("object"));
        assert!(items["properties"]["table_name"].is_object());
        assert_eq!(items["additionalProperties"], json!(true));
    }

    #[test]
    fn output_schema_matches_envelope_shape() {
        let schema = result_envelope_schema();
        assert_eq!(schema["type"], json!("object"));
        let rows = vec![json!({ "id": 1 })];
        let env = build_result_envelope(
            "u.get",
            "u.get",
            ":memory:",
            Some(&rows),
            Some(1),
            false,
            7,
            None,
            None,
        );
        let props = schema["properties"].as_object().expect("properties object");
        for key in env.as_object().expect("envelope object").keys() {
            assert!(props.contains_key(key), "schema missing key `{key}`");
        }
        assert_eq!(
            schema["properties"]["response"]["properties"]["rows"]["items"],
            json!({})
        );
    }
}
