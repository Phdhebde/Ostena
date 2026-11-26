//! A minimal `LDAPv3` client (ADR-0021): the subset the core needs to read
//! its directories, and nothing else.
//!
//! - **Operations**: simple bind, search (with the simple paged results
//!   control, RFC 2696), unbind. No write operation, no SASL, no `StartTLS`,
//!   no referral chasing.
//! - **Encoding**: a strict subset of BER ([`ber`](crate)), fuzzed
//!   (`fuzz/fuzz_targets/ldap_message.rs`, `ldap_filter.rs`).
//! - **Transport**: any `AsyncRead + AsyncWrite` stream, opened by the
//!   caller. The core only ever hands an LDAPS stream built with the
//!   directory profile of `ostena-crypto`: plain LDAP and `StartTLS` do not
//!   exist here.
//! - **Filters**: built as trees, so that a value typed by a user never
//!   changes the shape of a filter ([`Filter`]).
//!
//! The crate depends neither on the database nor on the API (CLAUDE.md:
//! protocol crates are testable and fuzzable alone).

#![forbid(unsafe_code)]

mod ber;
mod client;
mod error;
mod filter;
mod message;
#[cfg(feature = "testing")]
pub mod testing;

pub use client::{Connection, Found, Limits};
pub use error::{LdapError, result_name};
pub use filter::{Filter, MATCHING_RULE_IN_CHAIN};
pub use message::{
    Attribute, Control, Entry, LdapResult, MAX_FIELD, Message, NOTICE_OF_DISCONNECTION_OID,
    PAGED_RESULTS_OID, Request, Response, Scope, SearchRequest, decode_request, decode_response,
    encode_bind, encode_response, encode_search, encode_unbind,
};

/// Fuzzing entry points (`fuzz/`): never panic, whatever the input.
pub mod fuzz {
    /// Decodes `data` as a response, then as a request.
    pub fn messages(data: &[u8]) {
        let _ = crate::decode_response(data);
        let _ = crate::decode_request(data);
    }

    /// Parses `data` as a filter in text form; a parsed filter must survive
    /// an encoding round trip.
    ///
    /// # Panics
    ///
    /// When an accepted filter does not round-trip: a finding.
    pub fn filter(data: &[u8]) {
        let Ok(text) = std::str::from_utf8(data) else {
            return;
        };
        let Ok(filter) = crate::Filter::parse(text) else {
            return;
        };
        let search = crate::SearchRequest {
            base: String::new(),
            scope: crate::Scope::Base,
            size_limit: 0,
            time_limit: 0,
            filter,
            attributes: Vec::new(),
        };
        let mut out = Vec::new();
        crate::encode_search(&mut out, 1, &search, &[]);
        let back = crate::decode_request(&out).ok().map(|m| m.op);
        assert_eq!(
            back,
            Some(crate::Request::Search(search)),
            "filter does not round-trip"
        );
    }
}
