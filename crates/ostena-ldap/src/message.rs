//! The `LDAPv3` messages of the subset (RFC 4511 § 4): simple bind, search,
//! unbind, and their responses, with the controls attached to a message.
//!
//! Both directions are encoded and decoded: the client writes requests and
//! reads responses; the test directory (feature `testing`) does the
//! reverse. The decoder is strict: unknown operations, trailing bytes inside
//! an element, non-UTF-8 names and out-of-range integers are refused.

use crate::LdapError;
use crate::ber::{self, Reader, tag};
use crate::filter::Filter;

/// The simple paged results control (RFC 2696).
pub const PAGED_RESULTS_OID: &str = "1.2.840.113556.1.4.319";
/// Notice of disconnection (RFC 4511 § 4.4.1).
pub const NOTICE_OF_DISCONNECTION_OID: &str = "1.3.6.1.4.1.1466.20036";
/// Longest diagnostic message kept from a response, characters.
pub(crate) const MAX_DIAGNOSTIC: usize = 256;

// Application tags of the protocol operations.
const BIND_REQUEST: u8 = 0x60;
const BIND_RESPONSE: u8 = 0x61;
const UNBIND_REQUEST: u8 = 0x42;
const SEARCH_REQUEST: u8 = 0x63;
const SEARCH_ENTRY: u8 = 0x64;
const SEARCH_DONE: u8 = 0x65;
const SEARCH_REFERENCE: u8 = 0x73;
const EXTENDED_RESPONSE: u8 = 0x78;
const CONTROLS: u8 = 0xa0;
const SIMPLE_AUTH: u8 = 0x80;
const REFERRAL: u8 = 0xa3;

/// A control attached to a message (RFC 4511 § 4.1.11).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Control {
    /// Its OID.
    pub oid: String,
    /// Whether the server must refuse the operation if it does not know it.
    pub critical: bool,
    /// Its value.
    pub value: Option<Vec<u8>>,
}

impl Control {
    /// A paged results control asking for `size` entries after `cookie`.
    pub fn paged(size: u32, cookie: &[u8]) -> Self {
        let mut value = Vec::new();
        ber::push_nested(&mut value, tag::SEQUENCE, |o| {
            ber::push_integer(o, tag::INTEGER, i64::from(size));
            ber::push(o, tag::OCTET_STRING, cookie);
        });
        Self {
            oid: PAGED_RESULTS_OID.into(),
            critical: true,
            value: Some(value),
        }
    }

    /// The size and cookie of a paged results control.
    ///
    /// # Errors
    ///
    /// [`LdapError::Malformed`] if it is another control or its value is
    /// invalid.
    pub fn as_paged(&self) -> Result<(u32, Vec<u8>), LdapError> {
        if self.oid != PAGED_RESULTS_OID {
            return Err(LdapError::Malformed("contrôle de pagination attendu"));
        }
        let value = self
            .value
            .as_deref()
            .ok_or(LdapError::Malformed("contrôle de pagination sans valeur"))?;
        let mut outer = Reader::new(value);
        let mut r = outer.nested(tag::SEQUENCE, "valeur du contrôle de pagination")?;
        outer.end("valeur du contrôle de pagination")?;
        let size = r.unsigned(tag::INTEGER, "taille de page")?;
        let cookie = r
            .expect(tag::OCTET_STRING, "cookie de pagination")?
            .to_vec();
        r.end("valeur du contrôle de pagination")?;
        Ok((size, cookie))
    }

    fn encode(&self, out: &mut Vec<u8>) {
        ber::push_nested(out, tag::SEQUENCE, |o| {
            ber::push(o, tag::OCTET_STRING, self.oid.as_bytes());
            if self.critical {
                ber::push_boolean(o, tag::BOOLEAN, true);
            }
            if let Some(v) = &self.value {
                ber::push(o, tag::OCTET_STRING, v);
            }
        });
    }

    fn decode(content: &[u8]) -> Result<Self, LdapError> {
        let mut r = Reader::new(content);
        let oid = r.utf8(tag::OCTET_STRING, "OID du contrôle")?.to_owned();
        let critical = match r.peek() {
            Some(tag::BOOLEAN) => r.boolean(tag::BOOLEAN, "criticité du contrôle")?,
            _ => false,
        };
        let value = r.optional(tag::OCTET_STRING)?.map(<[u8]>::to_vec);
        r.end("contrôle")?;
        Ok(Self {
            oid,
            critical,
            value,
        })
    }
}

/// Search scope (RFC 4511 § 4.5.1.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    /// The base entry only.
    Base,
    /// Its direct children.
    One,
    /// The base and the whole subtree.
    Subtree,
}

impl Scope {
    fn code(self) -> i64 {
        match self {
            Self::Base => 0,
            Self::One => 1,
            Self::Subtree => 2,
        }
    }
}

/// A search request. Aliases are never dereferenced and types are always
/// returned with their values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SearchRequest {
    /// Base DN.
    pub base: String,
    /// Scope.
    pub scope: Scope,
    /// Entries at most, asked of the server (0: no limit).
    pub size_limit: u32,
    /// Seconds at most, asked of the server (0: no limit).
    pub time_limit: u32,
    /// The filter.
    pub filter: Filter,
    /// Attributes to return; empty: all user attributes.
    pub attributes: Vec<String>,
}

/// A request of the subset.
#[derive(Debug, PartialEq, Eq)]
pub enum Request {
    /// Simple bind (decoded by the test directory only: the client writes
    /// its bind with [`encode_bind`], straight into a buffer it wipes).
    Bind {
        /// DN or name.
        name: String,
        /// Password.
        password: Vec<u8>,
    },
    /// Search.
    Search(SearchRequest),
    /// Unbind.
    Unbind,
}

/// The result of an operation (RFC 4511 § 4.1.9).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LdapResult {
    /// Result code; 0 is success.
    pub code: u32,
    /// Matched DN.
    pub matched: String,
    /// Diagnostic message, without control characters, truncated.
    pub diagnostic: String,
}

impl LdapResult {
    /// A success.
    pub fn success() -> Self {
        Self::with(0, "")
    }

    /// Code `code` with a diagnostic message.
    pub fn with(code: u32, diagnostic: &str) -> Self {
        Self {
            code,
            matched: String::new(),
            diagnostic: clean(diagnostic),
        }
    }

    /// `Ok` for a success, the refusal otherwise.
    ///
    /// # Errors
    ///
    /// [`LdapError::Refused`].
    pub fn check(&self) -> Result<(), LdapError> {
        if self.code == 0 {
            Ok(())
        } else {
            Err(LdapError::Refused {
                code: self.code,
                diagnostic: self.diagnostic.clone(),
            })
        }
    }

    fn encode(&self, out: &mut Vec<u8>) {
        ber::push_integer(out, tag::ENUMERATED, i64::from(self.code));
        ber::push(out, tag::OCTET_STRING, self.matched.as_bytes());
        ber::push(out, tag::OCTET_STRING, self.diagnostic.as_bytes());
    }

    fn decode(r: &mut Reader<'_>) -> Result<Self, LdapError> {
        let code = r.unsigned(tag::ENUMERATED, "code de résultat")?;
        let matched = r.expect(tag::OCTET_STRING, "DN correspondant")?;
        let diagnostic = r.expect(tag::OCTET_STRING, "message de diagnostic")?;
        // A referral is read and dropped: the client never follows one.
        r.optional(REFERRAL)?;
        Ok(Self {
            code,
            matched: String::from_utf8_lossy(matched).into_owned(),
            diagnostic: clean(&String::from_utf8_lossy(diagnostic)),
        })
    }
}

/// Without control characters, at most [`MAX_DIAGNOSTIC`] characters.
fn clean(text: &str) -> String {
    text.chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .take(MAX_DIAGNOSTIC)
        .collect::<String>()
        .trim()
        .to_owned()
}

/// An attribute of an entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attribute {
    /// Its description, as the server wrote it.
    pub name: String,
    /// Its values, as bytes (`objectGUID` is binary).
    pub values: Vec<Vec<u8>>,
}

/// A search result entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// Its DN.
    pub dn: String,
    /// Its attributes.
    pub attributes: Vec<Attribute>,
}

impl Entry {
    /// The values of `name` (case-insensitive), empty if absent. A range
    /// option (`member;range=0-1499`) is matched too.
    pub fn values(&self, name: &str) -> impl Iterator<Item = &[u8]> {
        self.attributes
            .iter()
            .filter(move |a| {
                let base = a.name.split(';').next().unwrap_or_default();
                base.eq_ignore_ascii_case(name)
            })
            .flat_map(|a| a.values.iter().map(Vec::as_slice))
    }

    /// The first value of `name`, if it is UTF-8.
    pub fn first(&self, name: &str) -> Option<&str> {
        self.values(name)
            .next()
            .and_then(|v| std::str::from_utf8(v).ok())
    }

    /// Whether the entry has `name`.
    pub fn has(&self, name: &str) -> bool {
        self.values(name).next().is_some()
    }
}

/// A response of the subset.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Response {
    /// Bind response.
    Bind(LdapResult),
    /// Search result entry.
    Entry(Entry),
    /// Search result reference (continuation URIs).
    Reference(Vec<String>),
    /// Search result done.
    Done(LdapResult),
    /// Extended response; only the notice of disconnection is expected.
    Extended {
        /// Its result.
        result: LdapResult,
        /// Its name (OID).
        name: Option<String>,
    },
}

/// A message: an identifier, an operation and controls.
#[derive(Debug, PartialEq, Eq)]
pub struct Message<T> {
    /// Message identifier; 0 only for unsolicited notifications.
    pub id: u32,
    /// The operation.
    pub op: T,
    /// Its controls.
    pub controls: Vec<Control>,
}

/// Longest DN, password or name in a request, bytes.
pub const MAX_FIELD: usize = 16 * 1024;

fn encode_message(out: &mut Vec<u8>, id: u32, controls: &[Control], op: impl FnOnce(&mut Vec<u8>)) {
    ber::push_nested(out, tag::SEQUENCE, |o| {
        ber::push_integer(o, tag::INTEGER, i64::from(id));
        op(o);
        if !controls.is_empty() {
            ber::push_nested(o, CONTROLS, |o| controls.iter().for_each(|c| c.encode(o)));
        }
    });
}

/// Writes a simple bind request into `out`, which is cleared and sized
/// first so that the password is written once and never moved by a
/// reallocation: the caller wipes `out` after sending it.
///
/// # Errors
///
/// [`LdapError::EmptyCredentials`] for an empty name or password (an
/// unauthenticated bind), [`LdapError::TooLong`] beyond [`MAX_FIELD`].
pub fn encode_bind(
    out: &mut Vec<u8>,
    id: u32,
    name: &str,
    password: &[u8],
) -> Result<(), LdapError> {
    if name.is_empty() || password.is_empty() {
        return Err(LdapError::EmptyCredentials);
    }
    if name.len() > MAX_FIELD || password.len() > MAX_FIELD {
        return Err(LdapError::TooLong(name.len().max(password.len())));
    }
    let mut id_bytes = Vec::with_capacity(8);
    ber::push_integer(&mut id_bytes, tag::INTEGER, i64::from(id));
    let bind_content = 3 + ber::element_len(name.len()) + ber::element_len(password.len());
    let message_content = id_bytes.len() + ber::element_len(bind_content);
    out.clear();
    out.reserve_exact(ber::element_len(message_content));
    ber::push_header(out, tag::SEQUENCE, message_content);
    out.extend_from_slice(&id_bytes);
    ber::push_header(out, BIND_REQUEST, bind_content);
    ber::push_integer(out, tag::INTEGER, 3);
    ber::push(out, tag::OCTET_STRING, name.as_bytes());
    ber::push_header(out, SIMPLE_AUTH, password.len());
    out.extend_from_slice(password);
    Ok(())
}

/// Writes a search request.
pub fn encode_search(out: &mut Vec<u8>, id: u32, search: &SearchRequest, controls: &[Control]) {
    encode_message(out, id, controls, |o| {
        ber::push_nested(o, SEARCH_REQUEST, |o| {
            ber::push(o, tag::OCTET_STRING, search.base.as_bytes());
            ber::push_integer(o, tag::ENUMERATED, search.scope.code());
            // derefAliases: neverDerefAliases.
            ber::push_integer(o, tag::ENUMERATED, 0);
            ber::push_integer(o, tag::INTEGER, i64::from(search.size_limit));
            ber::push_integer(o, tag::INTEGER, i64::from(search.time_limit));
            ber::push_boolean(o, tag::BOOLEAN, false);
            search.filter.encode(o);
            ber::push_nested(o, tag::SEQUENCE, |o| {
                for a in &search.attributes {
                    ber::push(o, tag::OCTET_STRING, a.as_bytes());
                }
            });
        });
    });
}

/// Writes an unbind request.
pub fn encode_unbind(out: &mut Vec<u8>, id: u32) {
    encode_message(out, id, &[], |o| ber::push(o, UNBIND_REQUEST, &[]));
}

/// Writes a response (test directory).
pub fn encode_response(out: &mut Vec<u8>, id: u32, response: &Response, controls: &[Control]) {
    encode_message(out, id, controls, |o| match response {
        Response::Bind(result) => ber::push_nested(o, BIND_RESPONSE, |o| result.encode(o)),
        Response::Done(result) => ber::push_nested(o, SEARCH_DONE, |o| result.encode(o)),
        Response::Entry(entry) => ber::push_nested(o, SEARCH_ENTRY, |o| {
            ber::push(o, tag::OCTET_STRING, entry.dn.as_bytes());
            ber::push_nested(o, tag::SEQUENCE, |o| {
                for a in &entry.attributes {
                    ber::push_nested(o, tag::SEQUENCE, |o| {
                        ber::push(o, tag::OCTET_STRING, a.name.as_bytes());
                        ber::push_nested(o, tag::SET, |o| {
                            for v in &a.values {
                                ber::push(o, tag::OCTET_STRING, v);
                            }
                        });
                    });
                }
            });
        }),
        Response::Reference(uris) => ber::push_nested(o, SEARCH_REFERENCE, |o| {
            for u in uris {
                ber::push(o, tag::OCTET_STRING, u.as_bytes());
            }
        }),
        Response::Extended { result, name } => ber::push_nested(o, EXTENDED_RESPONSE, |o| {
            result.encode(o);
            if let Some(n) = name {
                ber::push(o, 0x8a, n.as_bytes());
            }
        }),
    });
}

/// Splits a complete message into its identifier, operation and controls.
/// A message split into its parts: id, operation tag, operation content,
/// controls.
type Parts<'a> = (u32, u8, &'a [u8], Vec<Control>);

fn split(bytes: &[u8]) -> Result<Parts<'_>, LdapError> {
    let mut outer = Reader::new(bytes);
    let mut r = outer.nested(tag::SEQUENCE, "message LDAP")?;
    outer.end("octets après le message")?;
    let id = r.unsigned(tag::INTEGER, "identifiant de message")?;
    if id > i32::MAX as u32 {
        return Err(LdapError::Malformed("identifiant de message"));
    }
    let (op, content) = r.any()?;
    let mut controls = Vec::new();
    if let Some(list) = r.optional(CONTROLS)? {
        let mut list = Reader::new(list);
        while !list.is_empty() {
            controls.push(Control::decode(list.expect(tag::SEQUENCE, "contrôle")?)?);
        }
    }
    r.end("octets après les contrôles")?;
    Ok((id, op, content, controls))
}

/// Reads a complete response message.
///
/// # Errors
///
/// [`LdapError::Malformed`].
pub fn decode_response(bytes: &[u8]) -> Result<Message<Response>, LdapError> {
    let (id, op, content, controls) = split(bytes)?;
    let mut r = Reader::new(content);
    let response = match op {
        BIND_RESPONSE => {
            let result = LdapResult::decode(&mut r)?;
            // serverSaslCreds, never used by a simple bind.
            r.optional(0x87)?;
            Response::Bind(result)
        }
        SEARCH_DONE => Response::Done(LdapResult::decode(&mut r)?),
        SEARCH_ENTRY => {
            let dn = r.utf8(tag::OCTET_STRING, "DN de l'entrée")?.to_owned();
            let mut list = r.nested(tag::SEQUENCE, "attributs de l'entrée")?;
            let mut attributes = Vec::new();
            while !list.is_empty() {
                let mut a = list.nested(tag::SEQUENCE, "attribut")?;
                let name = a.utf8(tag::OCTET_STRING, "nom d'attribut")?.to_owned();
                let mut set = a.nested(tag::SET, "valeurs d'attribut")?;
                a.end("attribut")?;
                let mut values = Vec::new();
                while !set.is_empty() {
                    values.push(set.expect(tag::OCTET_STRING, "valeur d'attribut")?.to_vec());
                }
                attributes.push(Attribute { name, values });
            }
            Response::Entry(Entry { dn, attributes })
        }
        SEARCH_REFERENCE => {
            let mut uris = Vec::new();
            while !r.is_empty() {
                uris.push(r.utf8(tag::OCTET_STRING, "référence")?.to_owned());
            }
            Response::Reference(uris)
        }
        EXTENDED_RESPONSE => {
            let result = LdapResult::decode(&mut r)?;
            let name = r
                .optional(0x8a)?
                .map(|n| String::from_utf8_lossy(n).into_owned());
            // responseValue, ignored.
            r.optional(0x8b)?;
            Response::Extended { result, name }
        }
        _ => return Err(LdapError::Malformed("opération de réponse inconnue")),
    };
    r.end("octets après la réponse")?;
    Ok(Message {
        id,
        op: response,
        controls,
    })
}

/// Reads a complete request message (test directory, fuzzing).
///
/// # Errors
///
/// [`LdapError::Malformed`].
pub fn decode_request(bytes: &[u8]) -> Result<Message<Request>, LdapError> {
    let (id, op, content, controls) = split(bytes)?;
    let mut r = Reader::new(content);
    let request = match op {
        BIND_REQUEST => {
            if r.unsigned(tag::INTEGER, "version")? != 3 {
                return Err(LdapError::Malformed("version LDAP autre que 3"));
            }
            let name = r.utf8(tag::OCTET_STRING, "nom de liaison")?.to_owned();
            let password = r.expect(SIMPLE_AUTH, "liaison simple attendue")?.to_vec();
            Request::Bind { name, password }
        }
        UNBIND_REQUEST if content.is_empty() => Request::Unbind,
        SEARCH_REQUEST => {
            let base = r.utf8(tag::OCTET_STRING, "base de recherche")?.to_owned();
            let scope = match r.unsigned(tag::ENUMERATED, "portée")? {
                0 => Scope::Base,
                1 => Scope::One,
                2 => Scope::Subtree,
                _ => return Err(LdapError::Malformed("portée")),
            };
            r.unsigned(tag::ENUMERATED, "derefAliases")?;
            let size_limit = r.unsigned(tag::INTEGER, "sizeLimit")?;
            let time_limit = r.unsigned(tag::INTEGER, "timeLimit")?;
            r.boolean(tag::BOOLEAN, "typesOnly")?;
            let filter = Filter::decode(&mut r, 0)?;
            let mut list = r.nested(tag::SEQUENCE, "attributs demandés")?;
            let mut attributes = Vec::new();
            while !list.is_empty() {
                attributes.push(list.utf8(tag::OCTET_STRING, "attribut demandé")?.to_owned());
            }
            Request::Search(SearchRequest {
                base,
                scope,
                size_limit,
                time_limit,
                filter,
                attributes,
            })
        }
        _ => return Err(LdapError::Malformed("opération de requête inconnue")),
    };
    r.end("octets après la requête")?;
    Ok(Message {
        id,
        op: request,
        controls,
    })
}

#[cfg(test)]
mod tests;
