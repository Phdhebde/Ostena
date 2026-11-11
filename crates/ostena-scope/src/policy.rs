//! Scope policy: specification, compilation and allocation-free decision.
//!
//! Decision order for a normalised address: floor (static, gateway addresses,
//! Ostena infrastructure) unless a development exception covers it, then deny
//! rules, then allow rules (default deny), then the port.

use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr};

use ostena_common::config::Mode;
pub use ostena_common::config::scope::{
    AllowRuleSpec, DenyRuleSpec, FloorExceptionSpec, InfrastructureRole, InfrastructureSpec,
    PolicySpec,
};

use crate::date::{DAY, Date};
use crate::error::{Code, Refusal, Rule};
use crate::floor::{FloorCause, static_floor};
use crate::local::LocalAddresses;
use crate::net::{Family, Network, PortRange, key, normalize};

/// Largest number of networks in a policy, to bound compilation.
pub const MAX_NETWORKS: usize = 100_000;

/// Shortest `short_names_justification` accepted in production.
pub const MIN_JUSTIFICATION_CHARS: usize = 20;

/// Furthest `short_names_expires` accepted, in days from today.
pub const MAX_WAIVER_DAYS: u64 = 366;

/// One problem found while compiling a policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyIssue {
    /// Stable code.
    pub code: Code,
    /// French message naming the field.
    pub message: String,
}

impl std::fmt::Display for PolicyIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[{}] {}", self.code, self.message)
    }
}

/// Every problem of a policy, reported at once.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyError(pub Vec<PolicyIssue>);

impl std::fmt::Display for PolicyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("politique de périmètre refusée :")?;
        self.0.iter().try_for_each(|i| write!(f, "\n  - {i}"))
    }
}

impl std::error::Error for PolicyError {}

impl PolicyError {
    /// Codes, in field order.
    pub fn codes(&self) -> Vec<Code> {
        self.0.iter().map(|i| i.code).collect()
    }
}

/// A weakening accepted at compilation, to log at startup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Weakening {
    /// Stable identifier of the weakened rule.
    pub kind: &'static str,
    /// French message.
    pub message: String,
}

/// Disjoint, sorted intervals mapped to a value. Lookup is a binary search.
#[derive(Debug, Clone, Default)]
struct IntervalMap {
    starts: Vec<u128>,
    ends: Vec<u128>,
    values: Vec<u32>,
}

impl IntervalMap {
    fn get(&self, k: u128) -> Option<u32> {
        let i = self.starts.partition_point(|s| *s <= k).checked_sub(1)?;
        (k <= self.ends[i]).then(|| self.values[i])
    }

    /// Splits possibly overlapping items into disjoint segments; `value` turns
    /// the set of covering items into the segment value. Adjacent segments
    /// with the same value are merged.
    fn build(
        items: &[(u128, u128, u32)],
        mut value: impl FnMut(&BTreeMap<u32, usize>) -> u32,
    ) -> Self {
        let mut events: Vec<(u128, bool, u32)> = Vec::with_capacity(items.len() * 2);
        for &(s, e, id) in items {
            events.push((s, true, id));
            if let Some(after) = e.checked_add(1) {
                events.push((after, false, id));
            }
        }
        events.sort_unstable();
        let mut map = Self::default();
        // A count per rule: one rule may list nested networks (0.0.0.0/0 and
        // 0.0.0.0/1); the end of the inner one must not deactivate the rule.
        let mut active: BTreeMap<u32, usize> = BTreeMap::new();
        let mut i = 0;
        while i < events.len() {
            let point = events[i].0;
            while i < events.len() && events[i].0 == point {
                let (_, start, id) = events[i];
                if start {
                    *active.entry(id).or_insert(0) += 1;
                } else if let Some(count) = active.get_mut(&id) {
                    *count -= 1;
                    if *count == 0 {
                        active.remove(&id);
                    }
                }
                i += 1;
            }
            if active.is_empty() {
                continue;
            }
            let end = events.get(i).map_or(u128::MAX, |next| next.0 - 1);
            let v = value(&active);
            let merge = map.values.last() == Some(&v)
                && map
                    .ends
                    .last()
                    .is_some_and(|e| e.checked_add(1) == Some(point));
            if merge {
                if let Some(last) = map.ends.last_mut() {
                    *last = end;
                }
            } else {
                map.starts.push(point);
                map.ends.push(end);
                map.values.push(v);
            }
        }
        map
    }
}

/// One map per address family.
#[derive(Debug, Clone, Default)]
struct FamilyMaps {
    v4: IntervalMap,
    v6: IntervalMap,
}

impl FamilyMaps {
    fn get(&self, family: Family, k: u128) -> Option<u32> {
        match family {
            Family::V4 => self.v4.get(k),
            Family::V6 => self.v6.get(k),
        }
    }

    fn build(
        items: &[(Family, u128, u128, u32)],
        mut value: impl FnMut(&BTreeMap<u32, usize>) -> u32,
    ) -> Self {
        let split = |f: Family| -> Vec<(u128, u128, u32)> {
            items
                .iter()
                .filter(|i| i.0 == f)
                .map(|i| (i.1, i.2, i.3))
                .collect()
        };
        Self {
            v4: IntervalMap::build(&split(Family::V4), &mut value),
            v6: IntervalMap::build(&split(Family::V6), &mut value),
        }
    }
}

/// The first rule index wins.
fn first(set: &BTreeMap<u32, usize>) -> u32 {
    set.keys().next().copied().unwrap_or(0)
}

/// An address accepted by [`CompiledPolicy::check`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Allowed {
    /// A development floor exception was needed (index in the specification).
    pub floor_exception: Option<u32>,
}

/// A policy ready for decisions.
#[derive(Debug, Clone)]
pub struct CompiledPolicy {
    gateway_group: String,
    allow: FamilyMaps,
    deny: FamilyMaps,
    infrastructure: FamilyMaps,
    exceptions: FamilyMaps,
    port_sets: Vec<Vec<PortRange>>,
    deny_labels: Vec<String>,
    infrastructure_roles: Vec<InfrastructureRole>,
    exception_reasons: Vec<String>,
    short_names: ShortNamesWaiver,
    weakenings: Vec<Weakening>,
}

/// Compiled `allow_short_names` waiver.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ShortNamesWaiver {
    Disabled,
    Allowed { expires: Option<Date> },
}

/// Whether single-label names are accepted at a given time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShortNames {
    /// Not allowed by the policy.
    Refused,
    /// Allowed (a weakening).
    Allowed,
    /// Allowed until a date that has passed.
    Expired,
}

impl CompiledPolicy {
    /// [`Self::compile_at`] with the system clock.
    ///
    /// # Errors
    ///
    /// See [`Self::compile_at`].
    pub fn compile(spec: &PolicySpec, mode: Mode) -> Result<Self, PolicyError> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        Self::compile_at(spec, mode, now)
    }

    /// Validates and compiles a specification for the given run mode, at
    /// `now` (Unix seconds).
    ///
    /// # Errors
    ///
    /// Every problem at once: invalid network, port or empty rule
    /// (`SCP-E012`), floor exception in production (`SCP-E013`), short names
    /// allowed in production without justification (`SCP-E015`), with a
    /// justification under 20 characters or an invalid, missing or too distant
    /// expiry (`SCP-E017`), or with an expired waiver (`SCP-E018`).
    pub fn compile_at(spec: &PolicySpec, mode: Mode, now: u64) -> Result<Self, PolicyError> {
        let total = spec.allow.iter().map(|r| r.networks.len()).sum::<usize>()
            + spec.deny.iter().map(|r| r.networks.len()).sum::<usize>()
            + spec
                .infrastructure
                .iter()
                .map(|r| r.networks.len())
                .sum::<usize>();
        if total > MAX_NETWORKS {
            return Err(PolicyError(vec![PolicyIssue {
                code: Code::InvalidPolicy,
                message: format!("{total} réseaux, au-delà du maximum de {MAX_NETWORKS}"),
            }]));
        }
        let mut c = Checker::default();
        if spec.gateway_group.trim().is_empty() {
            c.issue(Code::InvalidPolicy, "gateway_group est vide".into());
        }

        // Allow rules: ports per rule, merged where rules overlap.
        let mut allow_items = Vec::new();
        let mut rule_ports: Vec<Vec<PortRange>> = Vec::with_capacity(spec.allow.len());
        for (r, rule) in spec.allow.iter().enumerate() {
            let field = format!("allow[{r}]");
            c.networks(&field, &rule.networks, r, &mut allow_items);
            rule_ports.push(c.ports(&field, &rule.ports));
        }
        let mut deny_items = Vec::new();
        for (r, rule) in spec.deny.iter().enumerate() {
            c.networks(&format!("deny[{r}]"), &rule.networks, r, &mut deny_items);
        }
        let mut infra_items = Vec::new();
        for (r, rule) in spec.infrastructure.iter().enumerate() {
            c.networks(
                &format!("infrastructure[{r}]"),
                &rule.networks,
                r,
                &mut infra_items,
            );
        }
        let exception_items = c.floor_exceptions(&spec.floor_exceptions, mode);
        let short_names = c.short_names(spec, mode, now);

        let Checker { issues, weakenings } = c;
        if !issues.is_empty() {
            return Err(PolicyError(issues));
        }

        let mut port_sets: Vec<Vec<PortRange>> = Vec::new();
        let allow = FamilyMaps::build(&allow_items, |active| {
            let mut ranges: Vec<PortRange> = active
                .keys()
                .flat_map(|r| rule_ports[*r as usize].iter().copied())
                .collect();
            let set = merge_ports(&mut ranges);
            let id = port_sets.iter().position(|s| *s == set).unwrap_or_else(|| {
                port_sets.push(set);
                port_sets.len() - 1
            });
            u32::try_from(id).unwrap_or(u32::MAX)
        });

        Ok(Self {
            gateway_group: spec.gateway_group.clone(),
            allow,
            deny: FamilyMaps::build(&deny_items, first),
            infrastructure: FamilyMaps::build(&infra_items, first),
            exceptions: FamilyMaps::build(&exception_items, first),
            port_sets,
            deny_labels: spec
                .deny
                .iter()
                .enumerate()
                .map(|(i, r)| r.label.clone().unwrap_or_else(|| format!("deny[{i}]")))
                .collect(),
            infrastructure_roles: spec.infrastructure.iter().map(|r| r.role).collect(),
            exception_reasons: spec
                .floor_exceptions
                .iter()
                .map(|e| e.reason.clone())
                .collect(),
            short_names,
            weakenings,
        })
    }

    /// Decides for one address and port. Never allocates.
    ///
    /// # Errors
    ///
    /// The [`Refusal`], with the rule that refused.
    pub fn check(&self, addr: SocketAddr, local: &LocalAddresses) -> Result<Allowed, Refusal> {
        let (ip, original) = normalize(addr.ip());
        let port = addr.port();
        let (family, k) = key(ip);
        let refuse = |code: Code, rule: Rule| Refusal {
            code,
            address: ip,
            original,
            port,
            rule,
        };
        let exception = self.exceptions.get(family, k);
        if exception.is_none() {
            if let Some(cause) = static_floor(family, k) {
                return Err(refuse(Code::Floor, Rule::Floor(cause)));
            }
            if local.contains(ip) {
                return Err(refuse(Code::Floor, Rule::Floor(FloorCause::AgentAddress)));
            }
            if let Some(i) = self.infrastructure.get(family, k) {
                return Err(refuse(Code::Infrastructure, Rule::Infrastructure(i)));
            }
        }
        if let Some(i) = self.deny.get(family, k) {
            return Err(refuse(Code::Denied, Rule::Denied(i)));
        }
        let Some(set) = self.allow.get(family, k) else {
            return Err(refuse(Code::NotAllowed, Rule::NoAllowedNetwork));
        };
        if port == 0 {
            return Err(refuse(Code::PortNotAllowed, Rule::PortZero));
        }
        let ports = &self.port_sets[set as usize];
        let i = ports.partition_point(|r| r.end < port);
        if ports.get(i).is_none_or(|r| r.start > port) {
            return Err(refuse(Code::PortNotAllowed, Rule::PortNotAllowed));
        }
        Ok(Allowed {
            floor_exception: exception,
        })
    }

    /// Readable description of a rule, for messages and audit.
    pub fn describe(&self, rule: Rule) -> String {
        match rule {
            Rule::Floor(cause) => format!("plancher : {}", cause.description()),
            Rule::Infrastructure(i) => format!(
                "infrastructure Ostena : {}",
                self.infrastructure_roles
                    .get(i as usize)
                    .map_or("?", |r| r.as_str())
            ),
            Rule::Denied(i) => format!(
                "réseau interdit « {} »",
                self.deny_labels.get(i as usize).map_or("?", String::as_str)
            ),
            Rule::NoAllowedNetwork => "aucun réseau autorisé ne couvre l'adresse".into(),
            Rule::PortZero => "port 0".into(),
            Rule::PortNotAllowed => "port non autorisé pour ce réseau".into(),
        }
    }

    /// Stable rule identifier for audit, e.g. `floor:cloud-metadata`.
    pub fn rule_id(&self, rule: Rule) -> String {
        match rule {
            Rule::Floor(cause) => format!("floor:{}", cause.as_str()),
            Rule::Infrastructure(i) => format!("infrastructure[{i}]"),
            Rule::Denied(i) => format!("deny[{i}]"),
            Rule::NoAllowedNetwork => "default-deny".into(),
            Rule::PortZero => "port-zero".into(),
            Rule::PortNotAllowed => "port".into(),
        }
    }

    /// Reason of a floor exception.
    pub fn exception_reason(&self, i: u32) -> &str {
        self.exception_reasons
            .get(i as usize)
            .map_or("?", String::as_str)
    }

    /// Gateway group, for audit.
    pub fn gateway_group(&self) -> &str {
        &self.gateway_group
    }

    /// Whether single-label names are accepted at `now` (Unix seconds). Checked
    /// at every decision, so that an expired waiver stops applying without a
    /// restart.
    pub fn short_names_at(&self, now: u64) -> ShortNames {
        match self.short_names {
            ShortNamesWaiver::Disabled => ShortNames::Refused,
            ShortNamesWaiver::Allowed { expires: Some(d) } if now >= d.end_unix() => {
                ShortNames::Expired
            }
            ShortNamesWaiver::Allowed { .. } => ShortNames::Allowed,
        }
    }

    /// Last day of the short names waiver, if any.
    pub fn short_names_expires(&self) -> Option<String> {
        match self.short_names {
            ShortNamesWaiver::Allowed { expires: Some(d) } => Some(d.to_string()),
            _ => None,
        }
    }

    /// Weakenings accepted at compilation.
    pub fn weakenings(&self) -> &[Weakening] {
        &self.weakenings
    }

    /// Logs one `scope.weakening` warning per weakening.
    pub fn log_weakenings(&self) {
        for w in &self.weakenings {
            tracing::warn!(event = "scope.weakening", kind = w.kind, gateway_group = %self.gateway_group, "{}", w.message);
        }
    }
}

/// Collects every problem and weakening of a specification.
#[derive(Default)]
struct Checker {
    issues: Vec<PolicyIssue>,
    weakenings: Vec<Weakening>,
}

type Item = (Family, u128, u128, u32);

fn index(i: usize) -> u32 {
    u32::try_from(i).unwrap_or(u32::MAX)
}

impl Checker {
    fn issue(&mut self, code: Code, message: String) {
        self.issues.push(PolicyIssue { code, message });
    }

    /// Parses the networks of rule `rule` into `out`.
    fn networks(&mut self, field: &str, nets: &[String], rule: usize, out: &mut Vec<Item>) {
        if nets.is_empty() {
            self.issue(Code::InvalidPolicy, format!("{field}.networks est vide"));
        }
        for (i, n) in nets.iter().enumerate() {
            match Network::parse(n) {
                Ok(net) if net.is_inside_normalized_range() => self.issue(
                    Code::InvalidPolicy,
                    format!(
                        "{field}.networks[{i}] = « {n} » : forme IPv6 d'une IPv4, jugée comme \
                         l'IPv4 ; écrivez la règle en IPv4"
                    ),
                ),
                Ok(net) => {
                    let (family, s, e) = net.range();
                    out.push((family, s, e, index(rule)));
                }
                Err(e) => self.issue(
                    Code::InvalidPolicy,
                    format!("{field}.networks[{i}] = « {n} » : {}", e.message()),
                ),
            }
        }
    }

    fn ports(&mut self, field: &str, ports: &[String]) -> Vec<PortRange> {
        if ports.is_empty() {
            self.issue(Code::InvalidPolicy, format!("{field}.ports est vide"));
        }
        let mut out = Vec::with_capacity(ports.len());
        for (i, p) in ports.iter().enumerate() {
            match PortRange::parse(p) {
                Some(range) => out.push(range),
                None => self.issue(
                    Code::InvalidPolicy,
                    format!("{field}.ports[{i}] = « {p} » : attendu un port (1 à 65535) ou une plage a-b"),
                ),
            }
        }
        out
    }

    fn floor_exceptions(&mut self, exceptions: &[FloorExceptionSpec], mode: Mode) -> Vec<Item> {
        let mut out = Vec::new();
        for (r, exception) in exceptions.iter().enumerate() {
            let field = format!("floor_exceptions[{r}]");
            if mode == Mode::Production {
                self.issue(
                    Code::FloorExceptionInProduction,
                    format!("{field} : une exception au plancher n'est possible qu'en mode développement"),
                );
            }
            if exception.reason.trim().is_empty() {
                self.issue(Code::InvalidPolicy, format!("{field}.reason est vide"));
            }
            match Network::parse(&exception.network) {
                Ok(net) => {
                    let (family, s, e) = net.range();
                    out.push((family, s, e, index(r)));
                    self.weakenings.push(Weakening {
                        kind: "floor_exception",
                        message: format!(
                            "{field} : plancher levé pour {} ({})",
                            exception.network, exception.reason
                        ),
                    });
                }
                Err(e) => self.issue(
                    Code::InvalidPolicy,
                    format!(
                        "{field}.network = « {} » : {}",
                        exception.network,
                        e.message()
                    ),
                ),
            }
        }
        out
    }

    /// `allow_short_names` waiver. In production it needs a justification of
    /// at least [`MIN_JUSTIFICATION_CHARS`] characters and an expiry date,
    /// at most [`MAX_WAIVER_DAYS`] days ahead and not yet passed.
    fn short_names(&mut self, spec: &PolicySpec, mode: Mode, now: u64) -> ShortNamesWaiver {
        if !spec.allow_short_names {
            return ShortNamesWaiver::Disabled;
        }
        let justification = spec
            .short_names_justification
            .as_deref()
            .map(str::trim)
            .filter(|j| !j.is_empty());
        let expires = match spec.short_names_expires.as_deref() {
            None => None,
            Some(text) => {
                let date = Date::parse(text);
                if date.is_none() {
                    self.issue(
                        Code::ShortNamesWaiver,
                        format!(
                            "short_names_expires = « {text} » : date attendue au format AAAA-MM-JJ"
                        ),
                    );
                }
                date
            }
        };
        if let Some(d) = expires
            && d.end_unix() > now.saturating_add(MAX_WAIVER_DAYS * DAY)
        {
            self.issue(
                Code::ShortNamesWaiver,
                format!("short_names_expires = {d} : échéance à plus d'un an ({MAX_WAIVER_DAYS} jours au plus)"),
            );
        }
        if mode == Mode::Production {
            match justification {
                None => self.issue(
                    Code::ShortNamesInProduction,
                    "allow_short_names = true en production exige short_names_justification \
                     (les noms courts peuvent être résolus par LLMNR ou NetBIOS)"
                        .into(),
                ),
                Some(j) if j.chars().count() < MIN_JUSTIFICATION_CHARS => self.issue(
                    Code::ShortNamesWaiver,
                    format!(
                        "short_names_justification trop courte ({} caractères, {MIN_JUSTIFICATION_CHARS} au moins)",
                        j.chars().count()
                    ),
                ),
                Some(_) => {}
            }
            match expires {
                None if spec.short_names_expires.is_none() => self.issue(
                    Code::ShortNamesWaiver,
                    "allow_short_names = true en production exige short_names_expires (AAAA-MM-JJ)".into(),
                ),
                Some(d) if now >= d.end_unix() => self.issue(
                    Code::ShortNamesExpired,
                    format!("dérogation allow_short_names expirée le {d} ; démarrage refusé en production"),
                ),
                _ => {}
            }
        }
        self.weakenings.push(Weakening {
            kind: "allow_short_names",
            message: format!(
                "noms courts acceptés (risque LLMNR/NetBIOS) jusqu'au {} ; justification : {}",
                expires.map_or_else(
                    || "(sans échéance, mode développement)".into(),
                    |d| d.to_string()
                ),
                justification.unwrap_or("aucune (mode développement)")
            ),
        });
        ShortNamesWaiver::Allowed { expires }
    }
}

/// Sorts and merges overlapping or adjacent port ranges.
fn merge_ports(ranges: &mut [PortRange]) -> Vec<PortRange> {
    ranges.sort_unstable();
    let mut out: Vec<PortRange> = Vec::with_capacity(ranges.len());
    for r in ranges.iter() {
        match out.last_mut() {
            Some(last) if u32::from(r.start) <= u32::from(last.end) + 1 => {
                last.end = last.end.max(r.end);
            }
            _ => out.push(*r),
        }
    }
    out
}

/// Every address of a network, for tests: first, last and middle.
#[doc(hidden)]
pub fn sample_ip(family_v4: bool, k: u128) -> IpAddr {
    if family_v4 {
        #[expect(clippy::cast_possible_truncation, reason = "IPv4 keys fit in 32 bits")]
        IpAddr::V4((k as u32).into())
    } else {
        IpAddr::V6(k.into())
    }
}

#[cfg(test)]
mod tests;
