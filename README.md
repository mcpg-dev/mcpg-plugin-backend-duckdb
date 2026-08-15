# `mcpg-plugin-backend-duckdb`

Embedded DuckDB (OLAP) backend binding plugin for mcpg (binding `kind: duckdb`).
Runs
an operator-fixed analytical statement as MCP **tools** and **resources** — the
`?` placeholders are bound from CEL expressions evaluated against the tool
arguments (bound as SQL **parameters**, never string-interpolated, so
injection-safe), against an embedded DuckDB engine (no server).

Part of the cloud-analytics warehouse suite. The "warehouse-grade SQL with no
warehouse" complement to `snowflake` / `bigquery` — query local Parquet / CSV /
files (and S3 / HTTP via the optional `httpfs` extension) entirely in-process.

## How it works

One binding = one operator-fixed statement = one MCP tool (or resource). Per call:

1. Each `params[i]` CEL expression is evaluated against the call's `arguments`
   object, producing a value that is **bound** to the i-th `?`. Values cross as
   DuckDB bind variables — the statement text is operator-fixed and never
   templated from caller input, so a caller cannot alter the query.
2. A connection runs the statement. For a **file** database the connection is
   drawn from the binding's lazy pool and reused across calls (`init_sql` +
   `attach` run **once per pooled connection**, at open); for `:memory:` a fresh
   connection is opened **per call** and `init_sql` + `attach` are re-applied
   each time (see **Connection pooling** below). Rows are projected to JSON by
   column (capped at `max_rows`, which sets the envelope `truncated` flag).
3. SQL rejections and engine errors become a structured `downstreamError` (the
   gateway's `isError` signal); transient I/O / lock failures are retryable.

The engine is **embedded** — `duckdb` is compiled in via the `bundled` feature
(vendored C++), so there is no server and no system library to install. The
`duckdb` crate is synchronous; every engine call runs on a blocking thread.

## Security

DuckDB can read local files (`read_csv`, `read_parquet`, `ATTACH <file>`) and,
with `httpfs`, reach S3 / HTTP. Three controls fence that reach:

- **Operator-fixed statement.** Caller data reaches the engine only as bound
  parameters, never concatenated into SQL — injection is structurally
  impossible, and a caller cannot redirect the query at a file.
- **External-access default-deny.** `allow_external_access` defaults to **false**,
  which disables DuckDB external access at open: `read_csv` / `read_parquet` /
  `httpfs` / `ATTACH <file>` all fail before touching the filesystem or network.
  Set it `true` to opt into lake / S3 analytics.
- **Read-only guard.** With `read_only` (default), the engine opens a file
  database read-only **and** the statement must begin with a read-only keyword
  (`SELECT` / `WITH` / `SHOW` / `DESCRIBE` / `EXPLAIN`) — two defenses.

Secrets (e.g. S3 keys for `httpfs`) flow through `init_sql` `CREATE SECRET` /
`SET` statements using `${cred://…}` / `${env.X}` references the gateway
secret-resolver expands at config load — never committed. A bare `cred://` in any
field is rejected (it would reach DuckDB verbatim).

### External-file reads (`operation: read_file`) — config-origin path

`operation: read_file` reads rows from a Parquet / CSV file or glob via DuckDB's
`read_parquet` / `read_csv_auto` table functions. The single non-negotiable
safety rule:

- **The file path/glob is OPERATOR-CONFIG ONLY.** `read_file.path` is fixed in
  the binding spec and is **never** taken from a caller argument. The binding
  exposes no path argument at all, so a caller-supplied `path` in the call
  arguments is ignored — the read always targets the operator-fixed file. A
  caller-supplied path would be an arbitrary-file-read (**LFI** locally, **SSRF**
  over `httpfs`/S3/HTTP), so it is structurally impossible here.
- The only caller-derived inputs are the `?` binds in the operator-fixed
  `read_file.predicate`, which cross as **bound** parameters (injection-safe).
- `read_file` requires `allow_external_access: true` (it reads outside the
  database) and is rejected at register when access is off. Projection columns
  are validated as safe SQL identifiers; the path is single-quote-escaped (it is
  operator-fixed, so this only guards against a literal apostrophe).

## Configuration

| Field | Type | Default | Notes |
|---|---|---|---|
| `database` | string (required) | — | `:memory:` (ephemeral, per-call) or a file path. Operator-configured. |
| `operation` | enum | `query` | `query` / `list_tables` / `list_columns` / `read_file` (see **Operations** below). |
| `read_only` | bool | `true` | Opens file DBs read-only + enforces the statement read-only guard (`operation: query` only — the other ops are inherently read-only). |
| `allow_external_access` | bool | `false` | Allow `read_csv`/`read_parquet`/`httpfs`/`ATTACH <file>`. Required for `operation: read_file`. |
| `init_sql` | `[string]` | `[]` | SQL run once at open (e.g. `INSTALL httpfs; LOAD httpfs;`, `CREATE SECRET …`). For a pooled file DB this runs once **per pooled connection**, not per call. |
| `attach` | `[{alias, source, read_only}]` | `[]` | `ATTACH '<source>' AS <alias>`. `alias` must be a safe identifier. |
| `statement` | string | — | Operator-fixed; `?` placeholders bound from `params`. **Required** for `operation: query`; ignored by the others. |
| `catalog_filters` | object | `{}` | Introspection filters for `list_tables` / `list_columns` (see **Operations**). |
| `read_file` | object | — | External-file read config for `operation: read_file` (see **Operations**). |
| `params` | `[string]` | `[]` | Ordered CEL expressions; `params[i]` → the i-th `?` (used by `query` and the `read_file` predicate). |
| `query.statement_timeout_ms` | int | `30000` | Per-call open + query + read timeout. |
| `query.max_rows` | int | `100000` | Client-side cap; extra rows set `truncated`. |
| `pool_max_size` | int | `2` | Max pooled connections for a **file** DB (small read pool — DuckDB is single-writer). Ignored for `:memory:` (never pooled). |

> `:memory:` is opened fresh per call (ephemeral) — `init_sql` re-seeds it each
> time, and it is **never** pooled. For data that must persist across calls, use
> a file database (which is pooled — see **Connection pooling**).

### As a tool — query a Parquet lake on S3

```yaml
mcp:
  capabilities:
    tools:
      - name: analytics.region_revenue
        description: Quarterly revenue by region from the lake.
        input_schema:
          type: object
          properties: { quarter: { type: string } }
          required: [quarter]
        backend:
          kind: duckdb
          database: ":memory:"
          allow_external_access: true
          init_sql:
            - "INSTALL httpfs; LOAD httpfs;"
            - "CREATE SECRET s3 (TYPE S3, KEY_ID '${cred://aws/lake#access_key_id}', SECRET '${cred://aws/lake#secret_access_key}', REGION 'eu-west-1')"
          statement: "SELECT region, sum(amount) AS revenue FROM read_parquet('s3://acme-lake/sales/*.parquet') WHERE quarter = ? GROUP BY region"
          params: ["arguments.quarter"]       # bound to ? — injection-safe
          query:
            statement_timeout_ms: 60000
            max_rows: 10000
```

### As a tool — query a local file database

```yaml
      backend:
        kind: duckdb
        database: "/data/warehouse.duckdb"
        read_only: true
        statement: "SELECT id, name FROM customers WHERE id = ?"
        params: ["arguments.id"]
```

## Operations

The `operation` field selects what a binding does. `query` (the default) runs the
operator-fixed `statement`. Three other operations cover schema discovery and
external-file reads.

### `list_tables` / `list_columns` — schema introspection

Read-only schema discovery over the engine's `information_schema` views. No
caller SQL is involved: the plugin builds the introspection `SELECT` and **binds
every filter as a `?` parameter** (never interpolated), so a caller can only
narrow the metadata, never alter the query. Each filter is an operator-pinned
static value plus an optional `*_arg` (the per-call argument name); when the
argument is present as a string it overrides the static value. `list_columns`
requires a `table` (static) or `table_arg` (per-call) so it scopes to one table.

```yaml
      # List the tables/views in the `main` schema.
      backend:
        kind: duckdb
        database: "/data/warehouse.duckdb"
        operation: list_tables
        catalog_filters:
          schema: main            # bound as a ? param
          table_type_arg: kind    # optional caller filter (BASE TABLE / VIEW)
```

```yaml
      # Describe one table's columns; the caller names the table.
      backend:
        kind: duckdb
        database: "/data/warehouse.duckdb"
        operation: list_columns
        catalog_filters:
          schema: main
          table_arg: table        # caller value bound as a ? param
```

`list_tables` rows carry `table_catalog`, `table_schema`, `table_name`,
`table_type`; `list_columns` rows carry `table_name`, `column_name`, `data_type`,
`is_nullable`, `ordinal_position`. The `output_schema` for these ops types
`response.rows` to those columns.

### `read_file` — external Parquet / CSV reads

The HIGH-value DuckDB capability: read rows directly from a Parquet / CSV file or
glob via `read_parquet` / `read_csv_auto`, with no table in the database.

> **SAFETY — the path is config-origin only.** `read_file.path` is operator-fixed
> in the binding spec and is **never** a caller argument. The binding exposes no
> path argument, so a caller cannot redirect the read at an arbitrary file
> (LFI / SSRF). Only the `read_file.predicate` `?` binds carry caller input, as
> bound parameters. `read_file` requires `allow_external_access: true` and is
> rejected at register when it is off. See **Security → External-file reads**.

```yaml
      backend:
        kind: duckdb
        database: ":memory:"
        operation: read_file
        allow_external_access: true        # required for read_file
        read_file:
          path: "/data/sales/*.parquet"    # OPERATOR-FIXED — never a caller arg
          format: parquet                  # or `csv` (→ read_csv_auto)
          columns: [region, amount]        # optional projection (safe identifiers)
          predicate: "amount >= ?"         # optional; ? bound from params
        params: ["arguments.min"]          # bound to the predicate ? — injection-safe
        query:
          max_rows: 10000
```

For S3 / HTTP sources, enable `httpfs` and supply credentials via `init_sql`
`CREATE SECRET` exactly as in the query example above; the `path` becomes
`s3://…` / `https://…` but remains operator-fixed.

## MCP surfaces & composition

The same binding works on every MCP surface. The surface is selected by the
capability list the binding sits under plus a `surface:` knob; composition is via
`pipeline` steps and child tools.

### As a pipeline step

Inside a `kind: pipeline` binding, a DuckDB step uses the `duckdb` step
discriminator (the same tag as the top-level binding and the registry/dispatch
kind). The backend config fields are flattened next to
`id` / `kind`; `input_transform` shapes the step's arguments from prior steps.

```yaml
      backend:
        kind: pipeline
        pipeline_timeout_ms: 30000
        steps:
          - id: load
            kind: duckdb
            database: "/data/warehouse.duckdb"
            read_only: true
            statement: "SELECT region, sum(amount) AS revenue FROM sales WHERE quarter = ? GROUP BY region"
            params: ["arguments.quarter"]
            input_transform: "${arguments}"
          - id: summarize
            kind: transform
            expression: "{ 'top_region': steps.load.response.rows[0] }"
```

### As a resource

Place the binding under `mcp.capabilities.resources[]` with `surface: resource`.
Successful rows are reshaped into the `resources/read` `{contents:[…]}` body. Set
a static `uri:` or let the binding use the requested URI from the read call.

```yaml
  capabilities:
    resources:
      - name: warehouse.regions
        uri: "duckdb://warehouse/regions"
        backend:
          kind: duckdb
          database: "/data/warehouse.duckdb"
          surface: resource
          uri: "duckdb://warehouse/regions"
          statement: "SELECT region, revenue FROM region_totals"
```

### As a resource template — per-`{id}` reads

Place the binding under `mcp.capabilities.resource_templates[]` with a
`uri_template` and `surface: resource`, and declare a `read_query` — the
operator-fixed single-row read run on a `resources/read` of a concrete URI. The
gateway pre-extracts the template variables and supplies each `{var}` in the call
arguments as `arguments.<var>`; the `read_query`'s `?` placeholders bind from the
binding's `params` CEL expressions, so the extracted value binds SERVER-SIDE as a
query parameter — never interpolated into SQL (injection-safe). With `read_query`
set the binding may omit `statement`; the read is read-only-guarded just like
`statement`.

```yaml
  capabilities:
    resource_templates:
      - name: warehouse.order
        uri_template: "duckdb://orders/{id}"
        backend:
          kind: duckdb
          database: "/data/warehouse.duckdb"
          surface: resource
          read_query: "SELECT * FROM orders WHERE id = ?"
          params: ["arguments.id"]
```

A read of `duckdb://orders/42` binds `42` to the single `?` and returns the
matching row as the `{contents:[{uri, text, mimeType}]}` body keyed on the
concrete URI. A crafted `{id}` such as `42 OR 1=1` is carried as one opaque
scalar bind — it matches no row and never executes as SQL.

### As a prompt

Under `mcp.capabilities.prompts[]` with `surface: prompt`, rows are reshaped into
the `prompts/get` `{messages:[…]}` body.

```yaml
  capabilities:
    prompts:
      - name: warehouse.context
        backend:
          kind: duckdb
          database: "/data/warehouse.duckdb"
          surface: prompt
          statement: "SELECT region, revenue FROM region_totals"
```

### As a child tool

An LLM / generator binding can list this binding in its child-tool set, letting
the model call it during a turn. Child dispatch is governed by
`governance.child_invoke.enforce_gates` (depth cap + self-call cycle refusal
apply), so a read-only warehouse query is a safe child.

### Schemas & annotations

`output_schema` for the envelope wrapper is advertised in `tools/list`, and
`input_schema` is derived from the declared `params`. Operators should mark
read-only warehouse bindings explicitly so clients treat them as side-effect-free:

```yaml
        annotations: { read_only: true, open_world: false }
```

## Change-watching

A resource can subscribe to DuckDB changes through the plugin's second entity —
a **polling `watch_strategy`** (kind `duckdb_poll`). DuckDB has no native
change-push channel, so the strategy opens a short-lived connection and runs a
cheap read-only scalar **high-water query** (`tracking_query`) on a cadence,
emitting `notifications/resources/updated` whenever that scalar advances. The
first tick only records a baseline, so a watcher never fires spuriously at
startup.

**File-backed only.** A `:memory:` database (or an absent / empty `database`
path) opens a fresh empty engine on every connection, so it has no external
change source — `duckdb_poll` rejects it at watch start. Point the watch at the
same persistent file database the binding reads.

Attach it under a resource's `watch:` block. The watch carries its own
connection (it is not tied to the binding's profile) plus the tracking query:

```yaml
mcp.configurations[].resources[].watch:
  type: plugin
  kind: duckdb_poll
  database: "/data/warehouse.duckdb"
  read_only: true
  tracking_query: "SELECT max(updated_at) FROM events"
  interval_ms: 30000
```

**Watch spec fields**

| Field | Type | Default | Description |
|---|---|---|---|
| `database` | string | *(required)* | File database path. `:memory:` / empty is rejected (no external change source). |
| `read_only` | bool | `true` | Open the engine read-only. |
| `allow_external_access` | bool | `false` | Allow `read_csv` / `httpfs` / `ATTACH <file>` for the tracking query. |
| `init_sql` | string[] | `[]` | Operator SQL run once per tick connection before the tracking query. |
| `attach` | object[] | `[]` | ATTACH targets applied after `init_sql`. |
| `tracking_query` | string | *(required)* | Read-only scalar high-water query; its first-row first-column value is the cursor. |
| `interval_ms` | int | `60000` | Poll cadence (floored at 250 ms). |
| `timeout_ms` | int | `10000` | Per-tick open + statement budget. |

The `tracking_query` is held to the same read-only keyword guard as the backend
`statement`; an empty or non-read-only query is rejected at watch start. A tick
returning zero rows (or a NULL scalar) is treated as "no change"; transient
open / query failures are logged and retried on the next tick.

## Response envelope

```jsonc
{
  "toolName": "analytics.region_revenue",
  "profile":  "analytics.region_revenue",
  "request":  { "database": ":memory:" },
  "response": {
    "rows":  [ { "region": "emea", "revenue": 1200 } ],
    "count": 1,
    "truncated": false,
    "durationMs": 12
  },
  "downstreamError": null,        // non-null ⇒ isError:true (duckdb_error / transport_error)
  "downstreamErrors": [],
  "error": null
}
```

## Build / test

```bash
nx build mcpg-plugin-backend-duckdb
nx test  mcpg-plugin-backend-duckdb                                       # unit tests (real :memory: engine, no Docker)
cargo test -p mcpg-plugin-backend-duckdb --features integration-tests     # file-DB + read_csv path
nx lint  mcpg-plugin-backend-duckdb
```

The `bundled` feature compiles DuckDB's vendored C++ — the first build is slow
(multi-minute, high RAM). No system library or external service is required.

## Connection pooling

**File** databases reuse connections through a lazy `deadpool` pool (mirroring
the `mssql` / `oracle` backends). `duckdb::Connection` is `Send` (but `!Sync`,
rusqlite-style), which is all deadpool needs to move a pooled connection into the
blocking statement thread. The pool is built at `register_profile` but opens
**no** connection — and does not create the file — until the first call. The
engine guards (`read_only` open-mode, `allow_external_access=false`) and the
`init_sql` + `ATTACH` setup are applied at **open**, so every pooled connection
inherits them; that setup runs **once per pooled connection** rather than once
per call. Pooled connections are pinged with `SELECT 1` before reuse; a dead
handle is discarded and a fresh one opened. `pool_max_size` (default 2) caps the
pool — DuckDB is single-writer, so this is a small read pool; for `read_only`
file DBs several concurrent handles are fine.

`:memory:` is **never** pooled: each call opens a fresh, empty ephemeral engine
that `init_sql` re-seeds, so `:memory:` stays per-call ephemeral (pooling it
would silently make it persistent / shared). Use a file database for data that
must survive across calls.

## Scope / deferred

- **Query cancellation** — v1 bounds calls with the task timeout; DuckDB's
  `interrupt()` is a possible follow-on.
- **Rich type fidelity** — composite (LIST / STRUCT / MAP) and exotic types are
  stringified; scalars, decimals (as strings), blobs (base64) and temporals are
  projected directly.
