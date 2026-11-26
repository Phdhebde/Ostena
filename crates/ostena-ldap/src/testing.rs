//! An in-memory directory that answers this client (feature `testing`,
//! tests only): simple bind, search with the filters of the subset
//! (`LDAP_MATCHING_RULE_IN_CHAIN` and the bitwise AND rule of Active
//! Directory included), paged results, unbind.
//!
//! Like Active Directory, it accepts an unauthenticated bind (empty
//! password), so that a test can prove the client never sends one, and it
//! refuses a search before a successful bind.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::LdapError;
use crate::ber;
use crate::filter::{Filter, MATCHING_RULE_IN_CHAIN};
use crate::message::{
    self, Attribute, Control, Entry, LdapResult, PAGED_RESULTS_OID, Request, Response, Scope,
    SearchRequest,
};

/// Bitwise AND matching rule of Active Directory.
pub const MATCHING_RULE_BIT_AND: &str = "1.2.840.113556.1.4.803";

/// The directory content and counters.
#[derive(Debug, Default)]
pub struct Directory {
    entries: Vec<Entry>,
    passwords: HashMap<String, String>,
    binds: usize,
    searches: usize,
    /// Largest page served, whatever the client asks (0: as asked).
    pub max_page: usize,
}

fn same(a: &str, b: &str) -> bool {
    a.eq_ignore_ascii_case(b)
}

impl Directory {
    /// An empty directory.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds or replaces the entry `dn`.
    pub fn add(&mut self, dn: &str, attributes: &[(&str, &[&str])]) {
        self.remove(dn);
        self.entries.push(Entry {
            dn: dn.to_owned(),
            attributes: attributes
                .iter()
                .map(|(n, v)| Attribute {
                    name: (*n).to_owned(),
                    values: v.iter().map(|s| s.as_bytes().to_vec()).collect(),
                })
                .collect(),
        });
    }

    /// Removes the entry `dn`, if present.
    pub fn remove(&mut self, dn: &str) {
        self.entries.retain(|e| !same(&e.dn, dn));
    }

    /// Replaces the values of `name` in `dn` (an empty list removes it).
    pub fn set(&mut self, dn: &str, name: &str, values: &[&[u8]]) {
        if let Some(e) = self.entries.iter_mut().find(|e| same(&e.dn, dn)) {
            e.attributes.retain(|a| !same(&a.name, name));
            if !values.is_empty() {
                e.attributes.push(Attribute {
                    name: name.to_owned(),
                    values: values.iter().map(|v| v.to_vec()).collect(),
                });
            }
        }
    }

    /// Sets the password of `dn`.
    pub fn set_password(&mut self, dn: &str, password: &str) {
        self.passwords
            .insert(dn.to_ascii_lowercase(), password.to_owned());
    }

    /// Bind requests received so far, with a password or not.
    pub fn binds(&self) -> usize {
        self.binds
    }

    /// Searches answered so far (each page counts).
    pub fn searches(&self) -> usize {
        self.searches
    }

    fn entry(&self, dn: &str) -> Option<&Entry> {
        self.entries.iter().find(|e| same(&e.dn, dn))
    }

    /// The DN a bind name designates: a DN or a `userPrincipalName`.
    fn bind_dn(&self, name: &str) -> Option<String> {
        if let Some(e) = self.entry(name) {
            return Some(e.dn.to_ascii_lowercase());
        }
        self.entries
            .iter()
            .find(|e| {
                e.values("userPrincipalName")
                    .any(|v| v.eq_ignore_ascii_case(name.as_bytes()))
            })
            .map(|e| e.dn.to_ascii_lowercase())
    }

    fn in_scope(entry: &str, base: &str, scope: Scope) -> bool {
        let (entry, base) = (entry.to_ascii_lowercase(), base.to_ascii_lowercase());
        let parent = entry.split_once(',').map_or("", |(_, p)| p);
        match scope {
            Scope::Base => entry == base,
            Scope::One => parent == base,
            Scope::Subtree => {
                base.is_empty() || entry == base || entry.ends_with(&format!(",{base}"))
            }
        }
    }

    fn chain(&self, entry: &Entry, attr: &str, target: &[u8]) -> bool {
        let mut seen: Vec<Vec<u8>> = Vec::new();
        let mut queue: Vec<Vec<u8>> = entry.values(attr).map(<[u8]>::to_vec).collect();
        while let Some(v) = queue.pop() {
            if v.eq_ignore_ascii_case(target) {
                return true;
            }
            if seen.iter().any(|s| s.eq_ignore_ascii_case(&v)) {
                continue;
            }
            if let Some(next) = std::str::from_utf8(&v).ok().and_then(|dn| self.entry(dn)) {
                queue.extend(next.values(attr).map(<[u8]>::to_vec));
            }
            seen.push(v);
        }
        false
    }

    fn matches(&self, entry: &Entry, filter: &Filter) -> bool {
        let number = |v: &[u8]| std::str::from_utf8(v).ok()?.parse::<i64>().ok();
        match filter {
            Filter::And(list) => list.iter().all(|f| self.matches(entry, f)),
            Filter::Or(list) => list.iter().any(|f| self.matches(entry, f)),
            Filter::Not(f) => !self.matches(entry, f),
            Filter::Equal(a, v) | Filter::Approx(a, v) => {
                entry.values(a).any(|x| x.eq_ignore_ascii_case(v))
            }
            Filter::GreaterOrEqual(a, v) => entry.values(a).any(|x| match (number(x), number(v)) {
                (Some(x), Some(v)) => x >= v,
                _ => x >= v.as_slice(),
            }),
            Filter::LessOrEqual(a, v) => entry.values(a).any(|x| match (number(x), number(v)) {
                (Some(x), Some(v)) => x <= v,
                _ => x <= v.as_slice(),
            }),
            Filter::Present(a) => entry.has(a),
            Filter::Substrings {
                attr,
                initial,
                any,
                last,
            } => entry.values(attr).any(|x| {
                let x = x.to_ascii_lowercase();
                let mut rest = x.as_slice();
                if let Some(i) = initial {
                    let i = i.to_ascii_lowercase();
                    if !rest.starts_with(&i) {
                        return false;
                    }
                    rest = &rest[i.len()..];
                }
                for part in any {
                    let part = part.to_ascii_lowercase();
                    match rest.windows(part.len()).position(|w| w == part.as_slice()) {
                        Some(p) => rest = &rest[p + part.len()..],
                        None => return false,
                    }
                }
                last.as_ref()
                    .is_none_or(|l| rest.ends_with(&l.to_ascii_lowercase()))
            }),
            Filter::Extensible {
                rule, attr, value, ..
            } => match (rule.as_deref(), attr.as_deref()) {
                (Some(MATCHING_RULE_IN_CHAIN), Some(a)) => self.chain(entry, a, value),
                (Some(MATCHING_RULE_BIT_AND), Some(a)) => {
                    let Some(mask) = number(value) else {
                        return false;
                    };
                    entry
                        .values(a)
                        .any(|x| number(x).is_some_and(|x| x & mask == mask))
                }
                _ => false,
            },
        }
    }

    fn search(&mut self, s: &SearchRequest, offset: usize, page: usize) -> (Vec<Entry>, usize) {
        self.searches += 1;
        let all: Vec<&Entry> = self
            .entries
            .iter()
            .filter(|e| Self::in_scope(&e.dn, &s.base, s.scope) && self.matches(e, &s.filter))
            .collect();
        let page = match (page, self.max_page) {
            (0, 0) => all.len(),
            (0, m) => m,
            (p, 0) => p,
            (p, m) => p.min(m),
        };
        let wanted = |name: &str| {
            s.attributes.is_empty() || s.attributes.iter().any(|a| a == "*" || same(a, name))
        };
        let slice = all
            .iter()
            .skip(offset)
            .take(page)
            .map(|e| Entry {
                dn: e.dn.clone(),
                attributes: e
                    .attributes
                    .iter()
                    .filter(|a| wanted(&a.name))
                    .cloned()
                    .collect(),
            })
            .collect::<Vec<_>>();
        let next = offset + slice.len();
        (slice, if next < all.len() { next } else { 0 })
    }
}

async fn read_message<S: AsyncRead + Unpin>(stream: &mut S) -> Result<Vec<u8>, LdapError> {
    let mut header = vec![0u8; 2];
    stream.read_exact(&mut header).await?;
    let (head, len) = loop {
        if let Some(found) = ber::header_len(&header)? {
            break found;
        }
        let mut b = [0u8; 1];
        stream.read_exact(&mut b).await?;
        header.push(b[0]);
    };
    if len > 1 << 20 {
        return Err(LdapError::TooLong(len));
    }
    header.truncate(head);
    let mut content = vec![0u8; len];
    stream.read_exact(&mut content).await?;
    header.extend_from_slice(&content);
    Ok(header)
}

/// Serves `directory` on `stream` until the client unbinds or closes.
///
/// # Errors
///
/// [`LdapError`] for a malformed request or a broken stream.
pub async fn serve<S>(directory: Arc<Mutex<Directory>>, mut stream: S) -> Result<(), LdapError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut bound = false;
    loop {
        let bytes = match read_message(&mut stream).await {
            Ok(b) => b,
            Err(LdapError::Io(_)) => return Ok(()),
            Err(e) => return Err(e),
        };
        let request = message::decode_request(&bytes)?;
        let mut out = Vec::new();
        match request.op {
            Request::Unbind => return Ok(()),
            Request::Bind { name, password } => {
                let mut d = directory.lock().unwrap_or_else(PoisonError::into_inner);
                d.binds += 1;
                let result = if password.is_empty() {
                    // Unauthenticated bind, accepted like Active Directory.
                    bound = false;
                    LdapResult::success()
                } else {
                    let ok = d.bind_dn(&name).is_some_and(|dn| {
                        d.passwords
                            .get(&dn)
                            .is_some_and(|p| p.as_bytes() == password.as_slice())
                    });
                    bound = ok;
                    if ok {
                        LdapResult::success()
                    } else {
                        LdapResult::with(
                            49,
                            "80090308: LdapErr: DSID-0C09041C, comment: AcceptSecurityContext \
                             error, data 52e, v4f7c",
                        )
                    }
                };
                drop(d);
                message::encode_response(&mut out, request.id, &Response::Bind(result), &[]);
            }
            Request::Search(search) => {
                if bound {
                    let paged = request
                        .controls
                        .iter()
                        .find(|c| c.oid == PAGED_RESULTS_OID)
                        .map(Control::as_paged)
                        .transpose()?;
                    let (size, offset) = match &paged {
                        Some((size, cookie)) => (
                            usize::try_from(*size).unwrap_or(usize::MAX),
                            std::str::from_utf8(cookie)
                                .ok()
                                .and_then(|c| c.parse().ok())
                                .unwrap_or(0),
                        ),
                        None => (0, 0),
                    };
                    let (entries, next) = directory
                        .lock()
                        .unwrap_or_else(PoisonError::into_inner)
                        .search(&search, offset, size);
                    for entry in entries {
                        message::encode_response(
                            &mut out,
                            request.id,
                            &Response::Entry(entry),
                            &[],
                        );
                    }
                    let controls = if paged.is_some() {
                        let cookie = if next == 0 {
                            Vec::new()
                        } else {
                            next.to_string().into_bytes()
                        };
                        vec![Control::paged(0, &cookie)]
                    } else {
                        Vec::new()
                    };
                    let done = Response::Done(LdapResult::success());
                    message::encode_response(&mut out, request.id, &done, &controls);
                } else {
                    let done = Response::Done(LdapResult::with(1, "bind required"));
                    message::encode_response(&mut out, request.id, &done, &[]);
                }
            }
        }
        stream.write_all(&out).await?;
        stream.flush().await?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn groups() -> Directory {
        let mut d = Directory::new();
        d.add("cn=alice,dc=t", &[("objectClass", &["user"])]);
        d.add(
            "cn=g1,dc=t",
            &[("objectClass", &["group"]), ("member", &["cn=alice,dc=t"])],
        );
        d.add(
            "cn=g2,dc=t",
            &[("objectClass", &["group"]), ("member", &["cn=g1,dc=t"])],
        );
        d.add(
            "cn=g3,dc=t",
            &[("objectClass", &["group"]), ("member", &["cn=g3,dc=t"])],
        );
        d
    }

    #[test]
    fn nested_groups_and_cycles() {
        let mut d = groups();
        let s = SearchRequest {
            base: "dc=t".into(),
            scope: Scope::Subtree,
            size_limit: 0,
            time_limit: 0,
            filter: Filter::And(vec![
                Filter::equal("objectClass", "group"),
                Filter::in_chain("member", "cn=alice,dc=t"),
            ]),
            attributes: vec![],
        };
        let (found, _) = d.search(&s, 0, 0);
        let names: Vec<_> = found.iter().map(|e| e.dn.as_str()).collect();
        assert_eq!(names, ["cn=g1,dc=t", "cn=g2,dc=t"]);
    }

    #[test]
    fn bit_and_rule() {
        let mut d = Directory::new();
        d.add("cn=a,dc=t", &[("userAccountControl", &["514"])]);
        d.add("cn=b,dc=t", &[("userAccountControl", &["512"])]);
        let s = SearchRequest {
            base: "dc=t".into(),
            scope: Scope::One,
            size_limit: 0,
            time_limit: 0,
            filter: Filter::parse("(userAccountControl:1.2.840.113556.1.4.803:=2)").unwrap(),
            attributes: vec![],
        };
        let (found, _) = d.search(&s, 0, 0);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].dn, "cn=a,dc=t");
    }
}
