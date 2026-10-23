// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

use serde::{Deserialize, Serialize};

/// Audit logger settings. Plugin entries must set `destination` explicitly.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct AuditLoggerConfig {
    /// Where audit records go: `stderr` or the host's `tracing` subscriber.
    pub destination: AuditDestination,

    /// Optional sink name — surfaces in every record so a single
    /// audit collector can distinguish multiple deployments. Free-
    /// form string.
    #[serde(default)]
    pub source: Option<String>,
}

/// Where audit records are written.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditDestination {
    /// Write one JSON line per call to stderr.
    #[default]
    Stderr,
    /// Emit via `tracing::info!` at target `apl.audit`. Routed by
    /// the host's subscriber to wherever traces normally go.
    Tracing,
}
