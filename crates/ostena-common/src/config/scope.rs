//! Data types of the scope policy, as written in the configuration (ADR-0005).
//!
//! Only the data lives here, so that the whole configuration file is parsed
//! in one strict pass; `ostena-scope` validates and compiles it.

use serde::Deserialize;

/// Policy of one gateway group, as written in the configuration.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicySpec {
    /// Gateway group this policy applies to (for audit). In an agent
    /// configuration it comes from `agent.gateway_group`.
    #[serde(default)]
    pub gateway_group: String,
    /// Allowed networks and their ports. Empty: nothing is allowed.
    #[serde(default)]
    pub allow: Vec<AllowRuleSpec>,
    /// Denied networks; they always win over allowed ones.
    #[serde(default)]
    pub deny: Vec<DenyRuleSpec>,
    /// Ostena components, refused as targets whatever the policy.
    #[serde(default)]
    pub infrastructure: Vec<InfrastructureSpec>,
    /// Development only: networks where the floor is lifted.
    #[serde(default)]
    pub floor_exceptions: Vec<FloorExceptionSpec>,
    /// Accept single-label names (weakening, see ADR-0005).
    #[serde(default)]
    pub allow_short_names: bool,
    /// Required to allow short names in production (at least 20 characters);
    /// logged.
    #[serde(default)]
    pub short_names_justification: Option<String>,
    /// Last day (`YYYY-MM-DD`, UTC) short names are allowed; required in
    /// production, at most one year ahead.
    #[serde(default)]
    pub short_names_expires: Option<String>,
}

/// Allowed networks with their ports.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AllowRuleSpec {
    /// Name shown in audit events.
    #[serde(default)]
    pub label: Option<String>,
    /// CIDR networks or single addresses.
    pub networks: Vec<String>,
    /// Ports (`"22"`) or ranges (`"8000-8100"`).
    pub ports: Vec<String>,
}

/// Denied networks.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DenyRuleSpec {
    /// Name shown in audit events.
    #[serde(default)]
    pub label: Option<String>,
    /// CIDR networks or single addresses.
    pub networks: Vec<String>,
}

/// Role of an Ostena component.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[expect(missing_docs, reason = "component names")]
pub enum InfrastructureRole {
    Core,
    Vault,
    Audit,
    Postgresql,
}

impl InfrastructureRole {
    /// Name for messages and audit.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Core => "core",
            Self::Vault => "coffre-fort",
            Self::Audit => "audit",
            Self::Postgresql => "PostgreSQL",
        }
    }
}

/// Addresses of an Ostena component.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InfrastructureSpec {
    /// Component.
    pub role: InfrastructureRole,
    /// CIDR networks or single addresses.
    pub networks: Vec<String>,
}

/// Development-only lifting of the floor.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FloorExceptionSpec {
    /// Network where the floor does not apply.
    pub network: String,
    /// Why (logged).
    pub reason: String,
}
