//! Write once, read many files (ADR-0012, « Stockage en ajout seul ») on
//! Linux: the inode attributes `append only` (`chattr +a`) while a file is
//! written, then `immutable` (`chattr +i`) once it is sealed.
//!
//! - An append-only file can only be opened for appending: it cannot be
//!   truncated, overwritten, renamed, linked or removed.
//! - An immutable file cannot be changed at all: content, rights, name.
//!
//! Setting or clearing these attributes needs `CAP_LINUX_IMMUTABLE` and the
//! ownership of the file (or `CAP_FOWNER`), and a file system that supports
//! them (ext4, XFS, Btrfs, tmpfs since Linux 6.0). [`probe`] tells at
//! startup whether a directory allows them. They do not stop an account
//! that holds `CAP_LINUX_IMMUTABLE` itself (root, or the service), which
//! can clear them: they stop every other account, and mistakes.
//!
//! Other systems have no equivalent: every function returns
//! [`io::ErrorKind::Unsupported`].

use std::fs::File;
use std::io;
use std::path::Path;

/// The write-once state of a file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protection {
    /// Neither attribute.
    None,
    /// Append only (`+a`), being written.
    AppendOnly,
    /// Immutable (`+i`), sealed.
    Immutable,
}

/// Name of the probe file of [`probe`], removed afterwards.
const PROBE: &str = ".ostena-worm-probe";

/// The protection of `file`.
///
/// # Errors
///
/// The error of the system call; [`io::ErrorKind::Unsupported`] outside
/// Linux or on a file system without these attributes.
pub fn protection(file: &File) -> io::Result<Protection> {
    imp::protection(file)
}

/// Sets the protection of `file`, keeping its other attributes. Going from
/// [`Protection::AppendOnly`] to [`Protection::Immutable`] is one change.
///
/// # Errors
///
/// [`io::ErrorKind::PermissionDenied`] without `CAP_LINUX_IMMUTABLE` or
/// the ownership of the file; [`io::ErrorKind::Unsupported`] outside Linux
/// or on a file system without these attributes.
pub fn protect(file: &File, protection: Protection) -> io::Result<()> {
    imp::protect(file, protection)
}

/// Checks that files of `dir` can be made append only and immutable, with
/// a probe file created, protected, unprotected and removed.
///
/// # Errors
///
/// The first failure; a leftover probe file of an interrupted probe is
/// unprotected and removed first.
pub fn probe(dir: &Path) -> io::Result<()> {
    let path = dir.join(PROBE);
    match File::open(&path) {
        Ok(file) => {
            imp::protect(&file, Protection::None)?;
            drop(file);
            std::fs::remove_file(&path)?;
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    let file = std::fs::OpenOptions::new()
        .append(true)
        .create_new(true)
        .open(&path)?;
    let checked = (|| {
        imp::protect(&file, Protection::AppendOnly)?;
        if imp::protection(&file)? != Protection::AppendOnly {
            return Err(io::Error::other("attribut « ajout seul » non conservé"));
        }
        imp::protect(&file, Protection::Immutable)?;
        if imp::protection(&file)? != Protection::Immutable {
            return Err(io::Error::other("attribut « immuable » non conservé"));
        }
        Ok(())
    })();
    // Always unprotected, so that the probe file can be removed.
    let cleared = imp::protect(&file, Protection::None);
    drop(file);
    let removed = std::fs::remove_file(&path);
    checked?;
    cleared?;
    removed
}

#[cfg(target_os = "linux")]
#[allow(
    unsafe_code,
    reason = "FS_IOC_GETFLAGS and FS_IOC_SETFLAGS on an owned descriptor; documented and tested"
)]
mod imp {
    use std::fs::File;
    use std::io;
    use std::os::fd::AsRawFd;

    use super::Protection;

    /// `FS_APPEND_FL` of `linux/fs.h`.
    const APPEND: libc::c_int = 0x0000_0020;
    /// `FS_IMMUTABLE_FL` of `linux/fs.h`.
    const IMMUTABLE: libc::c_int = 0x0000_0010;

    fn flags(file: &File) -> io::Result<libc::c_int> {
        let mut flags: libc::c_int = 0;
        // SAFETY: the descriptor is open for the lifetime of `file`; the
        // kernel writes one `int` to the pointer (the ioctl number says
        // `long`, the kernel ABI is an `int`, as e2fsprogs uses it), which
        // points to a live local of that type.
        let rc = unsafe { libc::ioctl(file.as_raw_fd(), libc::FS_IOC_GETFLAGS, &raw mut flags) };
        if rc == 0 {
            Ok(flags)
        } else {
            Err(unsupported(io::Error::last_os_error()))
        }
    }

    /// `ENOTTY` (no such ioctl on this file system) reads as unsupported.
    fn unsupported(e: io::Error) -> io::Error {
        if e.raw_os_error() == Some(libc::ENOTTY) || e.raw_os_error() == Some(libc::EOPNOTSUPP) {
            io::Error::new(io::ErrorKind::Unsupported, e)
        } else {
            e
        }
    }

    pub(super) fn protection(file: &File) -> io::Result<Protection> {
        let flags = flags(file)?;
        Ok(if flags & IMMUTABLE != 0 {
            Protection::Immutable
        } else if flags & APPEND != 0 {
            Protection::AppendOnly
        } else {
            Protection::None
        })
    }

    pub(super) fn protect(file: &File, protection: Protection) -> io::Result<()> {
        let mut flags = flags(file)? & !(APPEND | IMMUTABLE);
        flags |= match protection {
            Protection::None => 0,
            Protection::AppendOnly => APPEND,
            Protection::Immutable => IMMUTABLE,
        };
        // SAFETY: as in `flags`: the kernel reads one `int` from a live
        // local; the descriptor is open for the lifetime of `file`.
        let rc = unsafe { libc::ioctl(file.as_raw_fd(), libc::FS_IOC_SETFLAGS, &raw const flags) };
        if rc == 0 {
            Ok(())
        } else {
            Err(unsupported(io::Error::last_os_error()))
        }
    }
}

#[cfg(not(target_os = "linux"))]
mod imp {
    use std::fs::File;
    use std::io;

    use super::Protection;

    fn unsupported() -> io::Error {
        io::Error::new(
            io::ErrorKind::Unsupported,
            "fichiers en ajout seul : Linux seulement",
        )
    }

    pub(super) fn protection(_: &File) -> io::Result<Protection> {
        Err(unsupported())
    }

    pub(super) fn protect(_: &File, _: Protection) -> io::Result<()> {
        Err(unsupported())
    }
}

#[cfg(test)]
mod tests;
