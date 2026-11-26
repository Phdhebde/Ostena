//! An `LDAPv3` client over any byte stream, one operation at a time.
//!
//! The stream is opened by the caller: in Ostena, always an LDAPS connection
//! built with the directory profile of `ostena-crypto` (ADR-0021). The
//! client has no `StartTLS` and no plain-text mode to fall back to.
//!
//! Every message read is bounded ([`Limits::max_message`]) before its
//! content is allocated, a search stops at [`Limits::max_entries`], and the
//! bind request, which carries the password, is written into a buffer sized
//! once and wiped as soon as it is sent.

use ostena_common::secret::SecretString;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use zeroize::Zeroize;

use crate::LdapError;
use crate::ber;
use crate::message::{
    self, Control, Entry, Message, NOTICE_OF_DISCONNECTION_OID, PAGED_RESULTS_OID, Response,
    SearchRequest,
};

/// Bounds of a connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Longest message read, bytes.
    pub max_message: usize,
    /// Most entries a search may return, all pages together.
    pub max_entries: usize,
    /// Entries asked per page (paged results control); 0 sends no control.
    pub page_size: u32,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_message: 4 * 1024 * 1024,
            max_entries: 200_000,
            page_size: 500,
        }
    }
}

/// What a search returned.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Found {
    /// The entries, every page together.
    pub entries: Vec<Entry>,
    /// Continuation references received, never followed.
    pub references: usize,
    /// Pages read.
    pub pages: usize,
}

/// An LDAP connection.
#[derive(Debug)]
pub struct Connection<S> {
    stream: S,
    next_id: u32,
    limits: Limits,
}

impl<S: AsyncRead + AsyncWrite + Unpin> Connection<S> {
    /// A connection over `stream`, already secured by the caller.
    pub fn new(stream: S, limits: Limits) -> Self {
        Self {
            stream,
            next_id: 1,
            limits,
        }
    }

    fn take_id(&mut self) -> u32 {
        let id = self.next_id;
        self.next_id = if id >= i32::MAX as u32 { 1 } else { id + 1 };
        id
    }

    async fn send(&mut self, bytes: &[u8]) -> Result<(), LdapError> {
        self.stream.write_all(bytes).await?;
        self.stream.flush().await?;
        Ok(())
    }

    /// Reads the next message, bounded by [`Limits::max_message`].
    async fn receive(&mut self) -> Result<Message<Response>, LdapError> {
        let mut header = [0u8; 6];
        self.stream.read_exact(&mut header[..2]).await?;
        if header[0] != 0x30 {
            return Err(LdapError::Malformed("message LDAP attendu"));
        }
        let mut have = 2;
        let (head, len) = loop {
            match ber::header_len(&header[..have])? {
                Some(found) => break found,
                None if have < header.len() => {
                    self.stream.read_exact(&mut header[have..=have]).await?;
                    have += 1;
                }
                None => return Err(LdapError::Malformed("en-tête trop long")),
            }
        };
        if len > self.limits.max_message {
            return Err(LdapError::TooLong(len));
        }
        let mut bytes = Vec::with_capacity(head + len);
        bytes.extend_from_slice(&header[..head]);
        bytes.resize(head + len, 0);
        self.stream.read_exact(&mut bytes[head..]).await?;
        let message = message::decode_response(&bytes)?;
        if message.id == 0 {
            return match message.op {
                Response::Extended { name, .. }
                    if name.as_deref() == Some(NOTICE_OF_DISCONNECTION_OID) =>
                {
                    Err(LdapError::Disconnected)
                }
                _ => Err(LdapError::Unexpected(
                    "notification non sollicitée inconnue",
                )),
            };
        }
        Ok(message)
    }

    /// Reads the response to `id`.
    async fn receive_for(&mut self, id: u32) -> Result<Message<Response>, LdapError> {
        let message = self.receive().await?;
        if message.id != id {
            return Err(LdapError::Unexpected("identifiant de message différent"));
        }
        Ok(message)
    }

    /// Simple bind as `name` with `password`.
    ///
    /// # Errors
    ///
    /// [`LdapError::EmptyCredentials`] before anything is sent for an empty
    /// name or password; [`LdapError::Refused`] if the server refuses
    /// (`invalidCredentials`: [`LdapError::is_invalid_credentials`]).
    pub async fn bind(&mut self, name: &str, password: &SecretString) -> Result<(), LdapError> {
        let id = self.take_id();
        let mut request = Vec::new();
        // SECRET-EXPOSURE: the password is written once into the bind
        // request, which is wiped right after it is sent.
        #[expect(clippy::disallowed_methods)]
        let encoded =
            message::encode_bind(&mut request, id, name, password.expose_secret().as_bytes());
        let sent = match encoded {
            Ok(()) => self.send(&request).await,
            Err(e) => Err(e),
        };
        request.zeroize();
        sent?;
        match self.receive_for(id).await?.op {
            Response::Bind(result) => result.check(),
            _ => Err(LdapError::Unexpected("réponse de liaison attendue")),
        }
    }

    /// Runs `search`, page after page, until the server has nothing more.
    ///
    /// # Errors
    ///
    /// [`LdapError::Refused`] if the server ends the search with an error,
    /// [`LdapError::TooManyEntries`] beyond [`Limits::max_entries`]; the
    /// connection should then be dropped.
    pub async fn search(&mut self, search: &SearchRequest) -> Result<Found, LdapError> {
        let mut found = Found::default();
        let mut cookie = Vec::new();
        loop {
            let id = self.take_id();
            let controls = if self.limits.page_size > 0 {
                vec![Control::paged(self.limits.page_size, &cookie)]
            } else {
                Vec::new()
            };
            let mut request = Vec::new();
            message::encode_search(&mut request, id, search, &controls);
            self.send(&request).await?;
            found.pages += 1;
            let done = loop {
                let message = self.receive_for(id).await?;
                match message.op {
                    Response::Entry(entry) => {
                        if found.entries.len() >= self.limits.max_entries {
                            return Err(LdapError::TooManyEntries(self.limits.max_entries));
                        }
                        found.entries.push(entry);
                    }
                    Response::Reference(_) => found.references += 1,
                    Response::Done(result) => break (result, message.controls),
                    _ => return Err(LdapError::Unexpected("réponse de recherche attendue")),
                }
            };
            let (result, controls) = done;
            result.check()?;
            let paged = controls.iter().find(|c| c.oid == PAGED_RESULTS_OID);
            match paged.map(Control::as_paged).transpose()? {
                Some((_, next)) if !next.is_empty() && self.limits.page_size > 0 => cookie = next,
                _ => return Ok(found),
            }
        }
    }

    /// Ends the session politely (no response is expected).
    ///
    /// # Errors
    ///
    /// [`LdapError::Io`].
    pub async fn unbind(&mut self) -> Result<(), LdapError> {
        let id = self.take_id();
        let mut request = Vec::new();
        message::encode_unbind(&mut request, id);
        self.send(&request).await?;
        self.stream.shutdown().await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use tokio::io::duplex;

    use super::*;
    use crate::filter::Filter;
    use crate::message::{LdapResult, Scope, encode_response};
    use crate::testing::{Directory, serve};

    fn secret(s: &str) -> SecretString {
        SecretString::from(s.to_owned())
    }

    fn rt() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
    }

    fn directory() -> Arc<Mutex<Directory>> {
        let mut d = Directory::new();
        d.add("dc=corp,dc=test", &[("objectClass", &["domain"])]);
        d.add(
            "cn=svc,dc=corp,dc=test",
            &[("objectClass", &["user"]), ("sAMAccountName", &["svc"])],
        );
        d.set_password("cn=svc,dc=corp,dc=test", "service-pw");
        for i in 0..25 {
            d.add(
                &format!("cn=u{i},dc=corp,dc=test"),
                &[
                    ("objectClass", &["user"]),
                    ("sAMAccountName", &[&format!("u{i}")]),
                ],
            );
        }
        Arc::new(Mutex::new(d))
    }

    fn users() -> SearchRequest {
        SearchRequest {
            base: "dc=corp,dc=test".into(),
            scope: Scope::Subtree,
            size_limit: 0,
            time_limit: 10,
            filter: Filter::parse("(&(objectClass=user)(sAMAccountName=u*))").unwrap(),
            attributes: vec!["sAMAccountName".into()],
        }
    }

    #[test]
    fn bind_and_paged_search() {
        rt().block_on(async {
            let dir = directory();
            let (client, server) = duplex(4096);
            tokio::spawn(serve(dir.clone(), server));
            let limits = Limits {
                page_size: 10,
                ..Limits::default()
            };
            let mut c = Connection::new(client, limits);
            c.bind("cn=svc,dc=corp,dc=test", &secret("service-pw"))
                .await
                .unwrap();
            let found = c.search(&users()).await.unwrap();
            assert_eq!(found.entries.len(), 25);
            assert_eq!(found.pages, 3);
            assert!(
                found
                    .entries
                    .iter()
                    .all(|e| e.first("samaccountname").is_some())
            );
            c.unbind().await.unwrap();
        });
    }

    #[test]
    fn search_limits() {
        rt().block_on(async {
            let (client, server) = duplex(4096);
            tokio::spawn(serve(directory(), server));
            let limits = Limits {
                page_size: 10,
                max_entries: 12,
                ..Limits::default()
            };
            let mut c = Connection::new(client, limits);
            c.bind("cn=svc,dc=corp,dc=test", &secret("service-pw"))
                .await
                .unwrap();
            assert_eq!(c.search(&users()).await, Err(LdapError::TooManyEntries(12)));
        });
    }

    #[test]
    fn wrong_password_and_empty_credentials() {
        rt().block_on(async {
            let dir = directory();
            let (client, server) = duplex(4096);
            tokio::spawn(serve(dir.clone(), server));
            let mut c = Connection::new(client, Limits::default());
            let e = c
                .bind("cn=svc,dc=corp,dc=test", &secret("wrong"))
                .await
                .unwrap_err();
            assert!(e.is_invalid_credentials(), "{e}");
            // The test directory, like Active Directory, would accept an
            // unauthenticated bind: the client never sends one.
            assert_eq!(
                c.bind("cn=svc,dc=corp,dc=test", &secret("")).await,
                Err(LdapError::EmptyCredentials)
            );
            assert_eq!(
                c.bind("", &secret("x")).await,
                Err(LdapError::EmptyCredentials)
            );
            assert_eq!(dir.lock().unwrap().binds(), 1);
            // Searching unbound is refused by the directory.
            assert!(matches!(
                c.search(&users()).await,
                Err(LdapError::Refused { .. })
            ));
        });
    }

    async fn answer(bytes: Vec<u8>) -> Result<(), LdapError> {
        let (client, mut server) = duplex(1 << 16);
        tokio::spawn(async move {
            let mut sink = [0u8; 512];
            let _ = server.read(&mut sink).await;
            let _ = server.write_all(&bytes).await;
        });
        let mut c = Connection::new(
            client,
            Limits {
                max_message: 1024,
                ..Limits::default()
            },
        );
        c.bind("cn=x", &secret("y")).await
    }

    #[test]
    fn hostile_answers() {
        rt().block_on(async {
            // Notice of disconnection.
            let mut out = Vec::new();
            encode_response(
                &mut out,
                0,
                &Response::Extended {
                    result: LdapResult::with(52, "bye"),
                    name: Some(NOTICE_OF_DISCONNECTION_OID.into()),
                },
                &[],
            );
            assert_eq!(answer(out).await, Err(LdapError::Disconnected));
            // Another message id.
            let mut out = Vec::new();
            encode_response(&mut out, 7, &Response::Bind(LdapResult::success()), &[]);
            assert!(matches!(answer(out).await, Err(LdapError::Unexpected(_))));
            // Too long, refused before the content is read.
            assert_eq!(
                answer(vec![0x30, 0x84, 0x10, 0, 0, 0]).await,
                Err(LdapError::TooLong(0x1000_0000))
            );
            // Not a sequence.
            assert!(matches!(
                answer(vec![0x04, 0x00]).await,
                Err(LdapError::Malformed(_))
            ));
            // Closed.
            assert!(matches!(answer(vec![]).await, Err(LdapError::Io(_))));
            // A bind answered with an entry.
            let mut out = Vec::new();
            encode_response(&mut out, 1, &Response::Done(LdapResult::success()), &[]);
            assert!(matches!(answer(out).await, Err(LdapError::Unexpected(_))));
        });
    }
}
