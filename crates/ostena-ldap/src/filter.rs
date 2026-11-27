//! Search filters (RFC 4511 § 4.5.1.7) and their text form (RFC 4515).
//!
//! A filter is built as a tree: a value typed by a user (a login name, a
//! DN) goes into a leaf as bytes and is never spliced into a filter string,
//! so it cannot change the shape of the filter (no LDAP injection). The text
//! parser is for the filters of the configuration only.

use crate::LdapError;
use crate::ber::{self, Reader, tag};

/// `LDAP_MATCHING_RULE_IN_CHAIN` of Active Directory: the transitive
/// closure of a DN-valued attribute (`member`, `memberOf`).
pub const MATCHING_RULE_IN_CHAIN: &str = "1.2.840.113556.1.4.1941";

/// Deepest nesting of `&`, `|` and `!` accepted, encoded or in text.
pub(crate) const MAX_DEPTH: usize = 16;
/// Longest filter in text form, bytes.
pub(crate) const MAX_TEXT: usize = 4096;

/// A search filter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Filter {
    /// All of them match (`&`).
    And(Vec<Filter>),
    /// One of them matches (`|`).
    Or(Vec<Filter>),
    /// It does not match (`!`).
    Not(Box<Filter>),
    /// `attr=value`.
    Equal(String, Vec<u8>),
    /// `attr>=value`.
    GreaterOrEqual(String, Vec<u8>),
    /// `attr<=value`.
    LessOrEqual(String, Vec<u8>),
    /// `attr~=value`.
    Approx(String, Vec<u8>),
    /// `attr=*`.
    Present(String),
    /// `attr=initial*any*…*final`.
    Substrings {
        /// Attribute description.
        attr: String,
        /// Leading part.
        initial: Option<Vec<u8>>,
        /// Middle parts, in order.
        any: Vec<Vec<u8>>,
        /// Trailing part.
        last: Option<Vec<u8>>,
    },
    /// `attr:dn:rule:=value`.
    Extensible {
        /// Matching rule OID.
        rule: Option<String>,
        /// Attribute description.
        attr: Option<String>,
        /// Asserted value.
        value: Vec<u8>,
        /// Whether the attributes of the DN are matched too.
        dn_attributes: bool,
    },
}

// Context-specific tags of the Filter CHOICE.
const AND: u8 = 0xa0;
const OR: u8 = 0xa1;
const NOT: u8 = 0xa2;
const EQUAL: u8 = 0xa3;
const SUBSTRINGS: u8 = 0xa4;
const GREATER: u8 = 0xa5;
const LESS: u8 = 0xa6;
const PRESENT: u8 = 0x87;
const APPROX: u8 = 0xa8;
const EXTENSIBLE: u8 = 0xa9;

impl Filter {
    /// `attr=value`, the value taken as is (no escaping needed).
    pub fn equal(attr: &str, value: impl Into<Vec<u8>>) -> Self {
        Self::Equal(attr.to_owned(), value.into())
    }

    /// `attr:1.2.840.113556.1.4.1941:=dn`: the entries whose `attr` reaches
    /// `dn` through any chain of DN values (nested groups of Active
    /// Directory).
    pub fn in_chain(attr: &str, dn: &str) -> Self {
        Self::Extensible {
            rule: Some(MATCHING_RULE_IN_CHAIN.to_owned()),
            attr: Some(attr.to_owned()),
            value: dn.as_bytes().to_vec(),
            dn_attributes: false,
        }
    }

    /// Appends the BER encoding.
    pub(crate) fn encode(&self, out: &mut Vec<u8>) {
        let ava = |out: &mut Vec<u8>, id: u8, attr: &str, value: &[u8]| {
            ber::push_nested(out, id, |o| {
                ber::push(o, tag::OCTET_STRING, attr.as_bytes());
                ber::push(o, tag::OCTET_STRING, value);
            });
        };
        match self {
            Self::And(list) | Self::Or(list) => {
                let id = if matches!(self, Self::And(_)) {
                    AND
                } else {
                    OR
                };
                ber::push_nested(out, id, |o| list.iter().for_each(|f| f.encode(o)));
            }
            Self::Not(inner) => ber::push_nested(out, NOT, |o| inner.encode(o)),
            Self::Equal(a, v) => ava(out, EQUAL, a, v),
            Self::GreaterOrEqual(a, v) => ava(out, GREATER, a, v),
            Self::LessOrEqual(a, v) => ava(out, LESS, a, v),
            Self::Approx(a, v) => ava(out, APPROX, a, v),
            Self::Present(a) => ber::push(out, PRESENT, a.as_bytes()),
            Self::Substrings {
                attr,
                initial,
                any,
                last,
            } => ber::push_nested(out, SUBSTRINGS, |o| {
                ber::push(o, tag::OCTET_STRING, attr.as_bytes());
                ber::push_nested(o, tag::SEQUENCE, |o| {
                    if let Some(i) = initial {
                        ber::push(o, 0x80, i);
                    }
                    for a in any {
                        ber::push(o, 0x81, a);
                    }
                    if let Some(l) = last {
                        ber::push(o, 0x82, l);
                    }
                });
            }),
            Self::Extensible {
                rule,
                attr,
                value,
                dn_attributes,
            } => ber::push_nested(out, EXTENSIBLE, |o| {
                if let Some(r) = rule {
                    ber::push(o, 0x81, r.as_bytes());
                }
                if let Some(a) = attr {
                    ber::push(o, 0x82, a.as_bytes());
                }
                ber::push(o, 0x83, value);
                if *dn_attributes {
                    ber::push_boolean(o, 0x84, true);
                }
            }),
        }
    }

    /// Reads one filter from `r`.
    pub(crate) fn decode(r: &mut Reader<'_>, depth: usize) -> Result<Self, LdapError> {
        if depth > MAX_DEPTH {
            return Err(LdapError::Malformed("filtre trop profond"));
        }
        let text = |b: &[u8]| {
            std::str::from_utf8(b)
                .map(str::to_owned)
                .map_err(|_| LdapError::Malformed("attribut du filtre non UTF-8"))
        };
        let (id, content) = r.any()?;
        let mut inner = Reader::new(content);
        let ava = |inner: &mut Reader<'_>| -> Result<(String, Vec<u8>), LdapError> {
            let attr = text(inner.expect(tag::OCTET_STRING, "attribut du filtre")?)?;
            let value = inner
                .expect(tag::OCTET_STRING, "valeur du filtre")?
                .to_vec();
            inner.end("assertion du filtre")?;
            Ok((attr, value))
        };
        Ok(match id {
            AND | OR => {
                let mut list = Vec::new();
                while !inner.is_empty() {
                    list.push(Self::decode(&mut inner, depth + 1)?);
                }
                if id == AND {
                    Self::And(list)
                } else {
                    Self::Or(list)
                }
            }
            NOT => {
                let f = Self::decode(&mut inner, depth + 1)?;
                inner.end("négation du filtre")?;
                Self::Not(Box::new(f))
            }
            EQUAL => ava(&mut inner).map(|(a, v)| Self::Equal(a, v))?,
            GREATER => ava(&mut inner).map(|(a, v)| Self::GreaterOrEqual(a, v))?,
            LESS => ava(&mut inner).map(|(a, v)| Self::LessOrEqual(a, v))?,
            APPROX => ava(&mut inner).map(|(a, v)| Self::Approx(a, v))?,
            PRESENT => Self::Present(text(content)?),
            SUBSTRINGS => {
                let attr = text(inner.expect(tag::OCTET_STRING, "attribut du filtre")?)?;
                let mut parts = inner.nested(tag::SEQUENCE, "sous-chaînes du filtre")?;
                inner.end("sous-chaînes du filtre")?;
                let (mut initial, mut any, mut last) = (None, Vec::new(), None);
                let mut position = 0u8;
                while !parts.is_empty() {
                    let (pid, value) = parts.any()?;
                    // initial, then any…, then final, each at most once
                    // except any (RFC 4511).
                    match pid {
                        0x80 if position == 0 => initial = Some(value.to_vec()),
                        0x81 if position <= 1 => any.push(value.to_vec()),
                        0x82 if position <= 1 => last = Some(value.to_vec()),
                        _ => return Err(LdapError::Malformed("sous-chaînes dans le désordre")),
                    }
                    position = match pid {
                        0x82 => 2,
                        _ => 1,
                    };
                }
                if initial.is_none() && any.is_empty() && last.is_none() {
                    return Err(LdapError::Malformed("sous-chaînes vides"));
                }
                Self::Substrings {
                    attr,
                    initial,
                    any,
                    last,
                }
            }
            EXTENSIBLE => {
                let rule = inner.optional(0x81)?.map(text).transpose()?;
                let attr = inner.optional(0x82)?.map(text).transpose()?;
                let value = inner.expect(0x83, "valeur de la règle étendue")?.to_vec();
                let dn_attributes = match inner.peek() {
                    Some(0x84) => inner.boolean(0x84, "dnAttributes")?,
                    _ => false,
                };
                inner.end("règle étendue")?;
                if rule.is_none() && attr.is_none() {
                    return Err(LdapError::Malformed("règle étendue sans règle ni attribut"));
                }
                Self::Extensible {
                    rule,
                    attr,
                    value,
                    dn_attributes,
                }
            }
            _ => return Err(LdapError::Malformed("choix de filtre inconnu")),
        })
    }

    /// Reads a filter in text form (RFC 4515), from the configuration.
    ///
    /// # Errors
    ///
    /// [`LdapError::Filter`].
    pub fn parse(text: &str) -> Result<Self, LdapError> {
        if text.len() > MAX_TEXT {
            return Err(LdapError::Filter("filtre trop long"));
        }
        let mut p = Parser {
            s: text.as_bytes(),
            i: 0,
        };
        let f = p.filter(0)?;
        if p.i != p.s.len() {
            return Err(LdapError::Filter("caractères après le filtre"));
        }
        Ok(f)
    }
}

struct Parser<'a> {
    s: &'a [u8],
    i: usize,
}

const fn bad(what: &'static str) -> LdapError {
    LdapError::Filter(what)
}

impl Parser<'_> {
    fn eat(&mut self, b: u8) -> bool {
        if self.s.get(self.i) == Some(&b) {
            self.i += 1;
            true
        } else {
            false
        }
    }

    fn filter(&mut self, depth: usize) -> Result<Filter, LdapError> {
        if depth > MAX_DEPTH {
            return Err(bad("filtre trop profond"));
        }
        if !self.eat(b'(') {
            return Err(bad("« ( » attendue"));
        }
        let f = match self.s.get(self.i) {
            Some(b'&' | b'|') => {
                let and = self.s[self.i] == b'&';
                self.i += 1;
                let mut list = Vec::new();
                while self.s.get(self.i) == Some(&b'(') {
                    list.push(self.filter(depth + 1)?);
                }
                if list.is_empty() {
                    return Err(bad("liste de filtres vide"));
                }
                if and {
                    Filter::And(list)
                } else {
                    Filter::Or(list)
                }
            }
            Some(b'!') => {
                self.i += 1;
                Filter::Not(Box::new(self.filter(depth + 1)?))
            }
            Some(_) => self.item()?,
            None => return Err(bad("filtre tronqué")),
        };
        if !self.eat(b')') {
            return Err(bad("« ) » attendue"));
        }
        Ok(f)
    }

    /// An attribute description or OID: letters, digits, `-`, `.`, `;`.
    fn attr(&mut self) -> &str {
        let start = self.i;
        while self
            .s
            .get(self.i)
            .is_some_and(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b';'))
        {
            self.i += 1;
        }
        // ASCII only: always valid UTF-8.
        std::str::from_utf8(&self.s[start..self.i]).unwrap_or_default()
    }

    /// A value up to `)` or, if `star`, up to `*` too; `\XX` escapes.
    fn value(&mut self, star: bool) -> Result<Vec<u8>, LdapError> {
        let mut out = Vec::new();
        while let Some(&b) = self.s.get(self.i) {
            match b {
                b')' => break,
                b'*' if star => break,
                b'(' | b'*' | 0 => return Err(bad("caractère à échapper dans une valeur")),
                b'\\' => {
                    let hex = self
                        .s
                        .get(self.i + 1..self.i + 3)
                        .and_then(|h| std::str::from_utf8(h).ok())
                        .and_then(|h| u8::from_str_radix(h, 16).ok())
                        .ok_or(bad("échappement \\XX invalide"))?;
                    out.push(hex);
                    self.i += 3;
                }
                _ => {
                    out.push(b);
                    self.i += 1;
                }
            }
        }
        Ok(out)
    }

    fn item(&mut self) -> Result<Filter, LdapError> {
        let attr = self.attr().to_owned();
        let rest = &self.s[self.i..];
        // Extensible match: attr[:dn][:rule]:=value or [:dn]:rule:=value.
        if rest.first() == Some(&b':') {
            let mut dn_attributes = false;
            let mut rule = None;
            while self.eat(b':') {
                if self.eat(b'=') {
                    let value = self.value(false)?;
                    if attr.is_empty() && rule.is_none() {
                        return Err(bad("règle étendue sans règle ni attribut"));
                    }
                    return Ok(Filter::Extensible {
                        rule,
                        attr: (!attr.is_empty()).then_some(attr),
                        value,
                        dn_attributes,
                    });
                }
                let word = self.attr().to_owned();
                // `:dn` once, before the rule; the rule once.
                if word.eq_ignore_ascii_case("dn") {
                    if dn_attributes || rule.is_some() {
                        return Err(bad("règle étendue invalide"));
                    }
                    dn_attributes = true;
                } else if !word.is_empty() && rule.is_none() {
                    rule = Some(word);
                } else {
                    return Err(bad("règle étendue invalide"));
                }
            }
            return Err(bad("« := » attendu"));
        }
        if attr.is_empty() {
            return Err(bad("attribut attendu"));
        }
        let op = match (rest.first(), rest.get(1)) {
            (Some(b'~'), Some(b'=')) => Some(b'~'),
            (Some(b'>'), Some(b'=')) => Some(b'>'),
            (Some(b'<'), Some(b'=')) => Some(b'<'),
            (Some(b'='), _) => None,
            _ => return Err(bad("opérateur attendu")),
        };
        self.i += if op.is_some() { 2 } else { 1 };
        if let Some(op) = op {
            let value = self.value(false)?;
            return Ok(match op {
                b'~' => Filter::Approx(attr, value),
                b'>' => Filter::GreaterOrEqual(attr, value),
                _ => Filter::LessOrEqual(attr, value),
            });
        }
        // `=`: equality, presence or substrings.
        let mut parts = vec![self.value(true)?];
        while self.eat(b'*') {
            parts.push(self.value(true)?);
        }
        if parts.len() == 1 {
            let value = parts.pop().unwrap_or_default();
            return Ok(Filter::Equal(attr, value));
        }
        if parts.len() == 2 && parts.iter().all(Vec::is_empty) {
            return Ok(Filter::Present(attr));
        }
        let last = parts.pop().filter(|p| !p.is_empty());
        let mut iter = parts.into_iter();
        let initial = iter.next().filter(|p| !p.is_empty());
        let any: Vec<_> = iter.collect();
        if any.iter().any(Vec::is_empty) {
            return Err(bad("« ** » dans une valeur"));
        }
        Ok(Filter::Substrings {
            attr,
            initial,
            any,
            last,
        })
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    fn round_trip(f: &Filter) -> Filter {
        let mut out = Vec::new();
        f.encode(&mut out);
        let mut r = Reader::new(&out);
        let back = Filter::decode(&mut r, 0).unwrap();
        assert!(r.is_empty());
        back
    }

    #[test]
    fn parses_the_usual_filters() {
        let f =
            Filter::parse("(&(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))")
                .unwrap();
        assert_eq!(
            f,
            Filter::And(vec![
                Filter::equal("objectClass", "user"),
                Filter::Not(Box::new(Filter::Extensible {
                    rule: Some("1.2.840.113556.1.4.803".into()),
                    attr: Some("userAccountControl".into()),
                    value: b"2".to_vec(),
                    dn_attributes: false,
                })),
            ])
        );
        assert_eq!(round_trip(&f), f);
        assert_eq!(
            Filter::parse("(uid=*)").unwrap(),
            Filter::Present("uid".into())
        );
        assert_eq!(
            Filter::parse("(cn=a*b*c)").unwrap(),
            Filter::Substrings {
                attr: "cn".into(),
                initial: Some(b"a".to_vec()),
                any: vec![b"b".to_vec()],
                last: Some(b"c".to_vec()),
            }
        );
        assert_eq!(
            Filter::parse("(cn=\\28x\\29)").unwrap(),
            Filter::equal("cn", "(x)")
        );
        assert_eq!(
            Filter::parse("(:dn:2.5.13.5:=x)").unwrap(),
            Filter::Extensible {
                rule: Some("2.5.13.5".into()),
                attr: None,
                value: b"x".to_vec(),
                dn_attributes: true,
            }
        );
        let f = Filter::parse("(|(a>=1)(b<=2)(c~=3))").unwrap();
        assert_eq!(round_trip(&f), f);
    }

    #[test]
    fn refuses_bad_filters() {
        for bad in [
            "",
            "objectClass=user",
            "(objectClass=user",
            "(objectClass=user))",
            "(&)",
            "(=x)",
            "(cn=a(b)",
            "(cn=\\zz)",
            "(cn=a**b)",
            "(:=x)",
            "(cn:dn:dn:=x)",
        ] {
            assert!(Filter::parse(bad).is_err(), "{bad}");
        }
        let deep = format!(
            "{}(a=b){}",
            "(!".repeat(MAX_DEPTH + 2),
            ")".repeat(MAX_DEPTH + 2)
        );
        assert!(Filter::parse(&deep).is_err());
    }

    #[test]
    fn a_user_value_cannot_change_the_shape() {
        let f = Filter::equal("sAMAccountName", "*)(objectClass=*");
        let mut out = Vec::new();
        f.encode(&mut out);
        let back = Filter::decode(&mut Reader::new(&out), 0).unwrap();
        assert_eq!(back, f);
    }

    #[test]
    fn decode_refuses_deep_nesting() {
        let mut f = Filter::Present("a".into());
        for _ in 0..=MAX_DEPTH + 1 {
            f = Filter::Not(Box::new(f));
        }
        let mut out = Vec::new();
        f.encode(&mut out);
        assert!(Filter::decode(&mut Reader::new(&out), 0).is_err());
    }

    fn leaf() -> impl Strategy<Value = Filter> {
        let attr = "[a-zA-Z][a-zA-Z0-9-]{0,8}";
        let value = proptest::collection::vec(any::<u8>(), 0..8);
        prop_oneof![
            (attr, value.clone()).prop_map(|(a, v)| Filter::Equal(a, v)),
            (attr, value.clone()).prop_map(|(a, v)| Filter::GreaterOrEqual(a, v)),
            attr.prop_map(Filter::Present),
            (attr, value).prop_map(|(a, v)| Filter::Extensible {
                rule: Some(MATCHING_RULE_IN_CHAIN.into()),
                attr: Some(a),
                value: v,
                dn_attributes: false,
            }),
        ]
    }

    fn tree() -> impl Strategy<Value = Filter> {
        leaf().prop_recursive(4, 32, 4, |inner| {
            prop_oneof![
                proptest::collection::vec(inner.clone(), 1..4).prop_map(Filter::And),
                proptest::collection::vec(inner.clone(), 1..4).prop_map(Filter::Or),
                inner.prop_map(|f| Filter::Not(Box::new(f))),
            ]
        })
    }

    proptest! {
        #[test]
        fn encode_decode(f in tree()) {
            prop_assert_eq!(round_trip(&f), f);
        }

        #[test]
        fn parse_never_panics(s in "[()&|!=*:a-z0-9\\\\]{0,40}") {
            let _ = Filter::parse(&s);
        }

        #[test]
        fn decode_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..64)) {
            let _ = Filter::decode(&mut Reader::new(&bytes), 0);
        }
    }
}
