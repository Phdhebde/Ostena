//! Ostena infrastructure endpoints (`[[agent.infrastructure]]`), turned into
//! floor entries (`SCP-E016`). Names are resolved at startup and refreshed;
//! a refresh keeps the union of the previous and the new addresses for one
//! period, so that a DNS change never opens a gap (ADR-0007).

use std::collections::BTreeSet;

use ostena_common::config::{Code as ConfigCode, InfrastructureEndpoint};

use crate::net::Network;
use crate::policy::{InfrastructureRole, InfrastructureSpec};
use crate::resolve::Resolver;
use crate::target::{Host, parse_host};

/// An infrastructure name that cannot be resolved (`CFG-P010`).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("[{}] infrastructure {} : « {address} » ne peut pas être résolu ({reason})", ConfigCode::InfrastructureUnresolved, role.as_str())]
pub struct Unresolved {
    /// Component.
    pub role: InfrastructureRole,
    /// Address as written.
    pub address: String,
    /// Why.
    pub reason: String,
}

/// Resolves every endpoint into networks (IP addresses become /32 or /128).
///
/// # Errors
///
/// The first address that is neither a network nor a resolvable full name.
/// Single-label names are refused: they could be answered by LLMNR or NetBIOS.
pub async fn resolve<R: Resolver>(
    endpoints: &[InfrastructureEndpoint],
    resolver: &R,
) -> Result<Vec<InfrastructureSpec>, Unresolved> {
    let mut specs = Vec::with_capacity(endpoints.len());
    for endpoint in endpoints {
        let unresolved = |address: &str, reason: String| Unresolved {
            role: endpoint.role,
            address: address.to_owned(),
            reason,
        };
        let mut networks = BTreeSet::new();
        for address in &endpoint.addresses {
            if Network::parse(address).is_ok() {
                networks.insert(address.clone());
                continue;
            }
            match parse_host(address) {
                Ok(Host::Ip(ip)) => {
                    networks.insert(ip.to_string());
                }
                Ok(Host::Name(name)) if name.is_short() => {
                    return Err(unresolved(
                        address,
                        "nom court refusé (LLMNR, NetBIOS)".into(),
                    ));
                }
                Ok(Host::Name(name)) => {
                    let ips = resolver
                        .resolve(&name)
                        .await
                        .map_err(|e| unresolved(address, e.0))?;
                    if ips.is_empty() {
                        return Err(unresolved(address, "aucune adresse".into()));
                    }
                    networks.extend(ips.iter().map(ToString::to_string));
                }
                Err(e) => return Err(unresolved(address, e.message.into())),
            }
        }
        specs.push(InfrastructureSpec {
            role: endpoint.role,
            networks: networks.into_iter().collect(),
        });
    }
    Ok(specs)
}

/// Union of two resolutions, per role (previous addresses stay refused for
/// one more refresh period).
pub fn union(
    previous: &[InfrastructureSpec],
    current: &[InfrastructureSpec],
) -> Vec<InfrastructureSpec> {
    let mut out: Vec<InfrastructureSpec> = current.to_vec();
    for old in previous {
        match out.iter_mut().find(|s| s.role == old.role) {
            Some(spec) => {
                let mut all: BTreeSet<String> = spec.networks.drain(..).collect();
                all.extend(old.networks.iter().cloned());
                spec.networks = all.into_iter().collect();
            }
            None => out.push(old.clone()),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use std::future::Future;
    use std::net::IpAddr;
    use std::pin::pin;
    use std::task::{Context, Poll, Waker};

    use super::*;
    use crate::resolve::ResolveError;
    use crate::target::Hostname;

    struct Table(&'static [(&'static str, &'static [&'static str])]);

    impl Resolver for Table {
        fn resolve(
            &self,
            name: &Hostname,
        ) -> impl Future<Output = Result<Vec<IpAddr>, ResolveError>> + Send {
            let answer = self
                .0
                .iter()
                .find(|(n, _)| *n == name.as_str())
                .map(|(_, ips)| ips.iter().map(|s| s.parse().unwrap()).collect())
                .ok_or_else(|| ResolveError("NXDOMAIN".into()));
            std::future::ready(answer)
        }
    }

    fn block_on<F: Future>(f: F) -> F::Output {
        let mut f = pin!(f);
        match f.as_mut().poll(&mut Context::from_waker(Waker::noop())) {
            Poll::Ready(v) => v,
            Poll::Pending => unreachable!("table resolver is immediate"),
        }
    }

    fn endpoint(role: InfrastructureRole, addresses: &[&str]) -> InfrastructureEndpoint {
        InfrastructureEndpoint {
            role,
            addresses: addresses.iter().map(|s| (*s).to_owned()).collect(),
        }
    }

    const TABLE: Table = Table(&[("core.corp.example", &["10.0.0.5", "2001:db8::5"])]);

    #[test]
    fn names_addresses_and_networks() {
        let specs = block_on(resolve(
            &[
                endpoint(InfrastructureRole::Core, &["core.corp.example", "10.0.0.6"]),
                endpoint(InfrastructureRole::Postgresql, &["10.0.1.0/24"]),
            ],
            &TABLE,
        ))
        .unwrap();
        assert_eq!(specs[0].networks, ["10.0.0.5", "10.0.0.6", "2001:db8::5"]);
        assert_eq!(specs[1].networks, ["10.0.1.0/24"]);
    }

    #[test]
    fn unresolvable_and_short_names_fail() {
        let e = block_on(resolve(
            &[endpoint(InfrastructureRole::Vault, &["vault.corp.example"])],
            &TABLE,
        ))
        .unwrap_err();
        assert!(
            e.to_string()
                .starts_with("[CFG-P010] infrastructure coffre-fort"),
            "{e}"
        );
        let e = block_on(resolve(
            &[endpoint(InfrastructureRole::Core, &["core"])],
            &TABLE,
        ))
        .unwrap_err();
        assert!(e.reason.contains("nom court"));
        let e = block_on(resolve(
            &[endpoint(InfrastructureRole::Core, &["0x7f.1"])],
            &TABLE,
        ))
        .unwrap_err();
        assert!(e.reason.contains("ambiguë"), "{e}");
    }

    #[test]
    fn union_keeps_previous_addresses() {
        let old = [InfrastructureSpec {
            role: InfrastructureRole::Core,
            networks: vec!["10.0.0.5".into()],
        }];
        let new = [InfrastructureSpec {
            role: InfrastructureRole::Core,
            networks: vec!["10.0.0.9".into()],
        }];
        let merged = union(&old, &new);
        assert_eq!(merged[0].networks, ["10.0.0.5", "10.0.0.9"]);
        let audit = [InfrastructureSpec {
            role: InfrastructureRole::Audit,
            networks: vec!["10.0.2.1".into()],
        }];
        assert_eq!(union(&audit, &new).len(), 2);
    }
}
