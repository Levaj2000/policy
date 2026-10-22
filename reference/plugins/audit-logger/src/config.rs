// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
/// Audit logger settings.
///
/// No `Default`: `destination` is a choice the entry has to make, so an
/// audit entry that names no output fails the load instead of quietly
/// writing somewhere the operator never picked.
pub struct AuditLoggerConfig {
    /// Where audit records go. Required. `stderr` suits the demo
    /// (`docker compose logs -f`) and k8s sidecar log forwarding;
    /// `tracing` routes through whatever subscriber the host installed.
    pub destination: AuditDestination,

    /// Optional sink name — surfaces in every record so a single
    /// audit collector can distinguish multiple deployments. Free-
    /// form string.
    #[serde(default)]
    pub source: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
/// Where audit records are written. No variant is the default.
pub enum AuditDestination {
    /// Write one JSON line per call to stderr.
    Stderr,
    /// Emit via `tracing::info!` at target `apl.audit`. Routed by
    /// the host's subscriber to wherever traces normally go.
    Tracing,
}
