//! Addresses of the gateway host itself, part of the floor.
//!
//! The standard library cannot list interfaces; `if-addrs` does. The snapshot
//! is swapped atomically and refreshed periodically (DHCP, new interfaces).

use std::io;
use std::net::IpAddr;
use std::sync::mpsc::{self, RecvTimeoutError};
use std::sync::{Arc, RwLock};
use std::thread::JoinHandle;
use std::time::Duration;

use crate::net::{Family, key, normalize};

/// Default refresh period.
pub const DEFAULT_REFRESH: Duration = Duration::from_secs(60);

/// Sorted, normalised addresses of the gateway host.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LocalAddresses {
    v4: Vec<u128>,
    v6: Vec<u128>,
}

impl LocalAddresses {
    /// A snapshot from explicit addresses (tests, or the caller's own list).
    pub fn from_addrs(addrs: impl IntoIterator<Item = IpAddr>) -> Self {
        let mut out = Self::default();
        for ip in addrs {
            let (ip, _) = normalize(ip);
            match key(ip) {
                (Family::V4, k) => out.v4.push(k),
                (Family::V6, k) => out.v6.push(k),
            }
        }
        out.v4.sort_unstable();
        out.v4.dedup();
        out.v6.sort_unstable();
        out.v6.dedup();
        out
    }

    /// Every interface address of the host, with IPv4 broadcast addresses.
    ///
    /// # Errors
    ///
    /// The operating system refuses to list the interfaces.
    pub fn system() -> io::Result<Self> {
        let interfaces = if_addrs::get_if_addrs()?;
        let addrs = interfaces.iter().flat_map(|i| {
            let broadcast = match &i.addr {
                if_addrs::IfAddr::V4(v4) => v4.broadcast.map(IpAddr::V4),
                if_addrs::IfAddr::V6(v6) => v6.broadcast.map(IpAddr::V6),
            };
            std::iter::once(i.ip()).chain(broadcast)
        });
        Ok(Self::from_addrs(addrs))
    }

    /// Whether a normalised address belongs to the host. Never allocates.
    pub fn contains(&self, ip: IpAddr) -> bool {
        match key(ip) {
            (Family::V4, k) => self.v4.binary_search(&k).is_ok(),
            (Family::V6, k) => self.v6.binary_search(&k).is_ok(),
        }
    }

    /// Number of addresses.
    pub fn len(&self) -> usize {
        self.v4.len() + self.v6.len()
    }

    /// Whether the snapshot is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// A snapshot shared between the decision path and the refresher.
#[derive(Debug, Clone, Default)]
pub struct SharedLocalAddresses(Arc<RwLock<Arc<LocalAddresses>>>);

impl SharedLocalAddresses {
    /// Shares an initial snapshot.
    pub fn new(initial: LocalAddresses) -> Self {
        Self(Arc::new(RwLock::new(Arc::new(initial))))
    }

    /// The current snapshot (a reference count increment, no copy).
    pub fn snapshot(&self) -> Arc<LocalAddresses> {
        match self.0.read() {
            Ok(guard) => Arc::clone(&guard),
            Err(poisoned) => Arc::clone(&poisoned.into_inner()),
        }
    }

    /// Replaces the snapshot.
    pub fn replace(&self, next: LocalAddresses) {
        let next = Arc::new(next);
        match self.0.write() {
            Ok(mut guard) => *guard = next,
            Err(poisoned) => *poisoned.into_inner() = next,
        }
    }
}

/// Background refresh of a [`SharedLocalAddresses`]; stops when dropped.
#[derive(Debug)]
pub struct Refresher {
    stop: Option<mpsc::Sender<()>>,
    handle: Option<JoinHandle<()>>,
}

impl Refresher {
    /// Reads the system addresses now (failing if impossible: the floor would
    /// be incomplete), then every `period` on a dedicated thread. A later
    /// failure keeps the previous snapshot and logs `scope.local_addresses_failed`.
    ///
    /// # Errors
    ///
    /// The first listing fails, or the thread cannot be started.
    pub fn start(shared: SharedLocalAddresses, period: Duration) -> io::Result<Self> {
        shared.replace(LocalAddresses::system()?);
        let (stop, stopped) = mpsc::channel::<()>();
        let handle = std::thread::Builder::new()
            .name("ostena-scope-local".into())
            .spawn(move || {
                while let Err(RecvTimeoutError::Timeout) = stopped.recv_timeout(period) {
                    match LocalAddresses::system() {
                        Ok(next) => shared.replace(next),
                        Err(e) => tracing::warn!(
                            event = "scope.local_addresses_failed",
                            "liste des adresses locales indisponible, ancienne liste conservée : {e}"
                        ),
                    }
                }
            })?;
        Ok(Self {
            stop: Some(stop),
            handle: Some(handle),
        })
    }
}

impl Drop for Refresher {
    fn drop(&mut self) {
        drop(self.stop.take());
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn contains_normalised_addresses() {
        let local = LocalAddresses::from_addrs([
            "10.0.0.5".parse().unwrap(),
            "::ffff:10.0.0.6".parse().unwrap(),
            "2001:db8::5".parse().unwrap(),
        ]);
        assert!(local.contains("10.0.0.5".parse().unwrap()));
        assert!(local.contains("10.0.0.6".parse().unwrap()));
        assert!(local.contains("2001:db8::5".parse().unwrap()));
        assert!(!local.contains("10.0.0.7".parse().unwrap()));
        assert_eq!(local.len(), 3);
    }

    #[test]
    fn system_lists_something() {
        let local = LocalAddresses::system().unwrap();
        // Every host has at least a loopback interface.
        assert!(!local.is_empty());
    }

    #[test]
    fn refresher_replaces_and_stops() {
        let shared = SharedLocalAddresses::new(LocalAddresses::default());
        assert!(shared.snapshot().is_empty());
        let refresher = Refresher::start(shared.clone(), Duration::from_millis(10)).unwrap();
        assert!(!shared.snapshot().is_empty());
        drop(refresher); // joins the thread
    }
}
