//! cdylib sync bridge — adapts the async [`DuckDbBackendPlugin`] onto the sync
//! FFI trait the cdylib vtable expects ([`SyncBackendPlugin`]). A private
//! multi-thread runtime `block_on`s the async methods (which internally run the
//! blocking DuckDB calls on `spawn_blocking`); the make-time [`HostHandle`] is
//! wrapped as `Arc<dyn BackendHost>` for `register_profile` and installed on the
//! inner plugin for observability. DuckDB is request/reply, so it inherits the
//! SDK's single-`Done` streaming default.

use std::sync::Arc;

use mcpg_plugin_protocol::{
    BackendError, BackendPlugin, BackendRequest, BackendResponse, PluginManifest, ResourcePage,
};
use mcpg_plugin_sdk::ffi::SyncBackendPlugin;
use mcpg_plugin_sdk::{HostHandle, HostHandleBackendHost};

use crate::DuckDbBackendPlugin;
use crate::watch::DuckDbWatchCdylib;

fn build_bridge_runtime(thread_name: &str) -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .thread_name(thread_name.to_owned())
        .enable_all()
        .build()
        .unwrap_or_else(|e| panic!("duckdb cdylib: tokio runtime init failed: {e}"))
}

/// `SyncBackendPlugin` bridge over [`DuckDbBackendPlugin`].
pub struct DuckDbBackendCdylib {
    inner: DuckDbBackendPlugin,
    host: Arc<dyn mcpg_plugin_protocol::BackendHost>,
    rt: tokio::runtime::Runtime,
}

impl DuckDbBackendCdylib {
    /// Infallible cdylib factory. `config_json` is ignored — DuckDB carries no
    /// plugin-level config (per-binding database / statement arrive via
    /// `register_profile`).
    pub fn from_host_config(_config_json: &str, host: HostHandle) -> Self {
        let inner = DuckDbBackendPlugin::new();
        let _installed = inner.set_host_handle(host.clone());
        Self {
            inner,
            host: Arc::new(HostHandleBackendHost::new(host)),
            rt: build_bridge_runtime("mcpg-backend-duckdb"),
        }
    }
}

impl SyncBackendPlugin for DuckDbBackendCdylib {
    fn manifest(&self) -> &PluginManifest {
        BackendPlugin::manifest(&self.inner)
    }

    fn kind(&self) -> &str {
        BackendPlugin::kind(&self.inner)
    }

    fn register_profile(
        &self,
        profile_name: &str,
        spec: &serde_json::Value,
    ) -> Result<(), BackendError> {
        self.rt.block_on(BackendPlugin::register_profile(
            &self.inner,
            profile_name,
            spec,
            Arc::clone(&self.host),
        ))
    }

    fn execute(
        &self,
        profile_name: &str,
        request: BackendRequest,
    ) -> Result<BackendResponse, BackendError> {
        self.rt
            .block_on(BackendPlugin::execute(&self.inner, profile_name, request))
    }

    fn audit_metadata(&self, profile_name: &str) -> serde_json::Map<String, serde_json::Value> {
        BackendPlugin::audit_metadata(&self.inner, profile_name)
    }

    fn list_resources(
        &self,
        profile_name: &str,
        cursor: Option<&str>,
    ) -> Result<ResourcePage, BackendError> {
        self.rt.block_on(BackendPlugin::list_resources(
            &self.inner,
            profile_name,
            cursor,
        ))
    }

    fn complete_template_variable(
        &self,
        profile_name: &str,
        variable_name: &str,
        prefix: &str,
        config: &serde_json::Value,
        context: &std::collections::BTreeMap<String, String>,
    ) -> Result<Vec<String>, BackendError> {
        self.rt.block_on(BackendPlugin::complete_template_variable(
            &self.inner,
            profile_name,
            variable_name,
            prefix,
            config,
            context,
        ))
    }
}

// cdylib export — two entities under `dev.mcpg.backend.duckdb`: the `backend`
// binding and the `watch_strategy` poller (kind `duckdb_poll`). The watch entity
// reuses the binding's filesystem-read / network-outbound capabilities for its
// tracking query (file DB read, plus external sources under
// `allow_external_access`); it self-describes via its `manifest()` slot and is
// distinguished by its `inner_name` slug.
mcpg_plugin_sdk::declare_plugin! {
    plugin_id: "dev.mcpg.backend.duckdb",
    plugin_version: env!("CARGO_PKG_VERSION"),
    descriptor_yaml: include_str!("../plugin.yaml"),
    capabilities: &[
        // Unscoped filesystem read — the readable paths (database file, attached
        // sources) are operator-configured per binding, so the static
        // declaration carries no path list. The precise `FilesystemRead{paths}`
        // is config-origin/runtime-derived from the resolved binding (like every
        // other file-backed backend); the plugin.yaml declares only
        // `network_outbound`.
        ::mcpg_plugin_protocol::capability::Capability::FilesystemRead {
            paths: ::std::vec::Vec::new(),
        },
        ::mcpg_plugin_protocol::capability::Capability::NetworkOutbound,
    ],
    // This kind may appear as a backend pipeline step, so it must declare
    // `pipeline_capable`. Every other fact is the behaviour-neutral default
    // (health Skip — embedded/in-process, opened per call; label = kind; no
    // dynamic list).
    backend_profile: ::mcpg_plugin_protocol::manifest::BackendProfile {
        pipeline_capable: true,
        ..::core::default::Default::default()
    },
    entities: [
        backend as binding {
            inner_name: "",
            plugin_type: DuckDbBackendCdylib,
            factory: |cfg, host: ::mcpg_plugin_sdk::HostHandle|
                DuckDbBackendCdylib::from_host_config(cfg, host),
        },
        watch_strategy as watch {
            inner_name: "watch",
            plugin_type: DuckDbWatchCdylib,
            factory: |cfg, host: ::mcpg_plugin_sdk::HostHandle|
                DuckDbWatchCdylib::from_host_config(cfg, host),
        },
    ],
}
