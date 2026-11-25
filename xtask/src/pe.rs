//! The DLLs a Windows executable (PE32 or PE32+) imports: statically
//! (import directory) and on first use (delay-load directory). Bounded,
//! never panics, standard library only (ADR-0009: no GUI or COM DLL in the
//! static imports of the agent).

/// DLLs that must never be imported statically by the agent, nor loaded
/// at rest: graphical interface and COM (ADR-0009).
pub(crate) const FORBIDDEN: [&str; 6] = [
    "user32.dll",
    "gdi32.dll",
    "win32u.dll",
    "combase.dll",
    "ole32.dll",
    "oleaut32.dll",
];

/// API sets (contracts the loader redirects to a DLL) that resolve to one of
/// the [`FORBIDDEN`] DLLs, by prefix: importing one statically loads the
/// DLL behind it. Each prefix ends at a `-`, so that `api-ms-win-core-com-`
/// does not catch `api-ms-win-core-comm-` (serial ports, kernelbase).
pub(crate) const FORBIDDEN_API_SETS: [&str; 11] = [
    // combase.dll
    "api-ms-win-core-com-",
    "api-ms-win-core-marshal-",
    "api-ms-win-core-winrt-",
    // ole32.dll, and the other COM contracts
    "ext-ms-win-com-",
    "ext-ms-win-ole32-",
    // user32.dll
    "ext-ms-win-ntuser-",
    "ext-ms-win-rtcore-ntuser-",
    "api-ms-win-rtcore-ntuser-",
    // gdi32.dll
    "ext-ms-win-gdi-",
    "ext-ms-win-rtcore-gdi-",
    "api-ms-win-gdi-",
];

/// A forbidden DLL, or an API set that resolves to one (`name` lower case).
pub(crate) fn is_forbidden(name: &str) -> bool {
    FORBIDDEN.contains(&name) || FORBIDDEN_API_SETS.iter().any(|p| name.starts_with(p))
}

/// The imports of an executable, lower case, in directory order.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct Imports {
    /// Loaded with the executable.
    pub(crate) static_dlls: Vec<String>,
    /// Loaded on first use (`/DELAYLOAD`).
    pub(crate) delayed: Vec<String>,
}

impl Imports {
    /// The forbidden DLLs, and API sets resolving to them, among the static
    /// imports.
    pub(crate) fn forbidden(&self) -> Vec<&str> {
        self.static_dlls
            .iter()
            .map(String::as_str)
            .filter(|d| is_forbidden(d))
            .collect()
    }
}

/// Most descriptors read in one directory.
const MAX_DESCRIPTORS: usize = 4096;
/// Longest DLL name.
const MAX_NAME: usize = 256;
/// Index of the import directory.
const IMPORT: usize = 1;
/// Index of the delay-load directory.
const DELAY_IMPORT: usize = 13;

fn u16_at(b: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes(
        b.get(at..at.checked_add(2)?)?.try_into().ok()?,
    ))
}

fn u32_at(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        b.get(at..at.checked_add(4)?)?.try_into().ok()?,
    ))
}

fn u64_at(b: &[u8], at: usize) -> Option<u64> {
    Some(u64::from_le_bytes(
        b.get(at..at.checked_add(8)?)?.try_into().ok()?,
    ))
}

struct Section {
    address: u32,
    size: u32,
    raw: u32,
    raw_size: u32,
}

struct Pe<'a> {
    bytes: &'a [u8],
    sections: Vec<Section>,
    image_base: u64,
    directories: Vec<(u32, u32)>,
}

impl Pe<'_> {
    /// The file offset of a relative virtual address.
    fn offset(&self, rva: u32) -> Option<usize> {
        let s = self.sections.iter().find(|s| {
            let end = s.address.saturating_add(s.size.max(s.raw_size));
            rva >= s.address && rva < end
        })?;
        let delta = rva - s.address;
        if delta >= s.raw_size {
            return None;
        }
        usize::try_from(s.raw.checked_add(delta)?).ok()
    }

    /// The NUL-terminated name at `rva`, lower case.
    fn name(&self, rva: u32) -> Option<String> {
        let at = self.offset(rva)?;
        let rest = self.bytes.get(at..)?;
        let end = rest.iter().take(MAX_NAME + 1).position(|&b| b == 0)?;
        let name = std::str::from_utf8(&rest[..end]).ok()?;
        name.bytes()
            .all(|b| b.is_ascii_graphic())
            .then(|| name.to_ascii_lowercase())
    }

    fn directory(&self, index: usize) -> Option<(u32, u32)> {
        self.directories
            .get(index)
            .copied()
            .filter(|&(rva, size)| rva != 0 && size != 0)
    }

    /// Names of a table of `stride`-byte descriptors whose name field is at
    /// `name_at`, until an all-zero descriptor.
    fn names(
        &self,
        index: usize,
        stride: usize,
        name_of: impl Fn(&[u8]) -> Option<u32>,
    ) -> Result<Vec<String>, String> {
        let Some((rva, _)) = self.directory(index) else {
            return Ok(Vec::new());
        };
        let start = self
            .offset(rva)
            .ok_or_else(|| format!("directory {index} outside the sections"))?;
        let mut names = Vec::new();
        for i in 0..MAX_DESCRIPTORS {
            let at = start + i * stride;
            let descriptor = self
                .bytes
                .get(at..at + stride)
                .ok_or_else(|| format!("directory {index} truncated"))?;
            if descriptor.iter().all(|&b| b == 0) {
                return Ok(names);
            }
            let name = name_of(descriptor)
                .and_then(|rva| self.name(rva))
                .ok_or_else(|| format!("directory {index}: invalid DLL name"))?;
            names.push(name);
        }
        Err(format!(
            "directory {index}: more than {MAX_DESCRIPTORS} entries"
        ))
    }
}

fn parse(bytes: &[u8]) -> Result<Pe<'_>, String> {
    let bad = |what: &str| format!("not a PE executable: {what}");
    if bytes.get(..2) != Some(b"MZ") {
        return Err(bad("no MZ header"));
    }
    let pe = u32_at(bytes, 0x3c).ok_or_else(|| bad("truncated DOS header"))? as usize;
    if bytes.get(pe..pe.saturating_add(4)) != Some(b"PE\0\0") {
        return Err(bad("no PE signature"));
    }
    let coff = pe + 4;
    let sections = usize::from(u16_at(bytes, coff + 2).ok_or_else(|| bad("truncated"))?);
    let optional_size = usize::from(u16_at(bytes, coff + 16).ok_or_else(|| bad("truncated"))?);
    let optional = coff + 20;
    let (base, count_at) = match u16_at(bytes, optional) {
        Some(0x10b) => (u64::from(u32_at(bytes, optional + 28).unwrap_or(0)), 92),
        Some(0x20b) => (u64_at(bytes, optional + 24).unwrap_or(0), 108),
        _ => return Err(bad("unknown optional header")),
    };
    let count = u32_at(bytes, optional + count_at).ok_or_else(|| bad("truncated"))? as usize;
    if count > 16 || count_at + 4 + count * 8 > optional_size {
        return Err(bad("invalid data directories"));
    }
    let directories = (0..count)
        .map(|i| {
            let at = optional + count_at + 4 + i * 8;
            Some((u32_at(bytes, at)?, u32_at(bytes, at + 4)?))
        })
        .collect::<Option<Vec<_>>>()
        .ok_or_else(|| bad("truncated data directories"))?;
    let table = optional + optional_size;
    let sections = (0..sections.min(96))
        .map(|i| {
            let at = table + i * 40;
            Some(Section {
                size: u32_at(bytes, at + 8)?,
                address: u32_at(bytes, at + 12)?,
                raw_size: u32_at(bytes, at + 16)?,
                raw: u32_at(bytes, at + 20)?,
            })
        })
        .collect::<Option<Vec<_>>>()
        .ok_or_else(|| bad("truncated section table"))?;
    Ok(Pe {
        bytes,
        sections,
        image_base: base,
        directories,
    })
}

/// Whether `bytes` starts like a PE executable.
pub(crate) fn is_pe(bytes: &[u8]) -> bool {
    bytes.get(..2) == Some(b"MZ")
}

/// The DLLs imported by the PE executable `bytes`.
///
/// # Errors
///
/// Not a PE executable, or a directory that cannot be read.
pub(crate) fn imports(bytes: &[u8]) -> Result<Imports, String> {
    let pe = parse(bytes)?;
    let static_dlls = pe.names(IMPORT, 20, |d| u32_at(d, 12))?;
    let image_base = pe.image_base;
    let delayed = pe.names(DELAY_IMPORT, 32, |d| {
        let name = u32_at(d, 4)?;
        // Bit 0 of the attributes: the fields are relative addresses; the
        // old format holds virtual addresses.
        if u32_at(d, 0)? & 1 == 1 {
            Some(name)
        } else {
            u32::try_from(u64::from(name).checked_sub(image_base)?).ok()
        }
    })?;
    Ok(Imports {
        static_dlls,
        delayed,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A PE32+ with one section at RVA 0x1000 (file offset 0x200) holding
    /// the import and delay-load directories of `statics` and `delayed`.
    fn synthetic(statics: &[&str], delayed: &[&str]) -> Vec<u8> {
        let mut b = vec![0u8; 0x600];
        b[..2].copy_from_slice(b"MZ");
        b[0x3c..0x40].copy_from_slice(&64u32.to_le_bytes());
        b[64..68].copy_from_slice(b"PE\0\0");
        let coff = 68;
        b[coff..coff + 2].copy_from_slice(&0x8664u16.to_le_bytes());
        b[coff + 2..coff + 4].copy_from_slice(&1u16.to_le_bytes());
        b[coff + 16..coff + 18].copy_from_slice(&240u16.to_le_bytes());
        let opt = coff + 20;
        b[opt..opt + 2].copy_from_slice(&0x20bu16.to_le_bytes());
        b[opt + 24..opt + 32].copy_from_slice(&0x1_4000_0000u64.to_le_bytes());
        b[opt + 108..opt + 112].copy_from_slice(&16u32.to_le_bytes());
        let dir = |b: &mut Vec<u8>, i: usize, rva: u32, size: u32| {
            let at = opt + 112 + i * 8;
            b[at..at + 4].copy_from_slice(&rva.to_le_bytes());
            b[at + 4..at + 8].copy_from_slice(&size.to_le_bytes());
        };
        dir(&mut b, IMPORT, 0x1000, 0x100);
        dir(&mut b, DELAY_IMPORT, 0x1100, 0x100);
        let sec = opt + 240;
        b[sec..sec + 8].copy_from_slice(b".idata\0\0");
        b[sec + 8..sec + 12].copy_from_slice(&0x400u32.to_le_bytes());
        b[sec + 12..sec + 16].copy_from_slice(&0x1000u32.to_le_bytes());
        b[sec + 16..sec + 20].copy_from_slice(&0x400u32.to_le_bytes());
        b[sec + 20..sec + 24].copy_from_slice(&0x200u32.to_le_bytes());
        // Names from RVA 0x1200 (offset 0x400).
        let mut name_rva = 0x1200u32;
        let mut put_name = |b: &mut Vec<u8>, name: &str| {
            let at = (name_rva - 0x1000 + 0x200) as usize;
            b[at..at + name.len()].copy_from_slice(name.as_bytes());
            let rva = name_rva;
            name_rva += u32::try_from(name.len()).unwrap() + 1;
            rva
        };
        for (i, name) in statics.iter().enumerate() {
            let rva = put_name(&mut b, name);
            let at = 0x200 + i * 20 + 12;
            b[at..at + 4].copy_from_slice(&rva.to_le_bytes());
        }
        for (i, name) in delayed.iter().enumerate() {
            let rva = put_name(&mut b, name);
            let at = 0x300 + i * 32;
            b[at..at + 4].copy_from_slice(&1u32.to_le_bytes());
            b[at + 4..at + 8].copy_from_slice(&rva.to_le_bytes());
        }
        b
    }

    #[test]
    fn reads_static_and_delayed_imports() {
        let b = synthetic(&["KERNEL32.dll", "ws2_32.dll"], &["OLEAUT32.dll"]);
        let imports = imports(&b).unwrap();
        assert_eq!(imports.static_dlls, ["kernel32.dll", "ws2_32.dll"]);
        assert_eq!(imports.delayed, ["oleaut32.dll"]);
        assert_eq!(imports.forbidden(), Vec::<&str>::new());
    }

    #[test]
    fn finds_forbidden_static_imports() {
        let b = synthetic(&["kernel32.dll", "OLEAUT32.dll", "user32.dll"], &[]);
        assert_eq!(
            imports(&b).unwrap().forbidden(),
            ["oleaut32.dll", "user32.dll"]
        );
    }

    #[test]
    fn finds_api_sets_of_forbidden_dlls() {
        let b = synthetic(
            &[
                "kernel32.dll",
                "api-ms-win-core-synch-l1-2-0.dll",
                "api-ms-win-core-comm-l1-1-0.dll",
                "API-MS-WIN-CORE-COM-L1-1-0.dll",
                "ext-ms-win-ntuser-window-l1-1-0.dll",
            ],
            &["ext-ms-win-gdi-dc-l1-2-0.dll"],
        );
        // Delay-loaded: allowed, like the DLLs themselves.
        assert_eq!(
            imports(&b).unwrap().forbidden(),
            [
                "api-ms-win-core-com-l1-1-0.dll",
                "ext-ms-win-ntuser-window-l1-1-0.dll"
            ]
        );
        for name in [
            "api-ms-win-core-com-midlproxystub-l1-1-0.dll",
            "api-ms-win-core-marshal-l1-1-0.dll",
            "api-ms-win-core-winrt-string-l1-1-0.dll",
            "api-ms-win-core-winrt-error-l1-1-1.dll",
            "ext-ms-win-com-ole32-l1-1-5.dll",
            "ext-ms-win-ole32-bindctx-l1-1-0.dll",
            "ext-ms-win-rtcore-ntuser-sysparams-l1-1-0.dll",
            "api-ms-win-rtcore-ntuser-window-l1-1-0.dll",
            "ext-ms-win-gdi-draw-l1-1-3.dll",
            "ext-ms-win-rtcore-gdi-devcaps-l1-1-0.dll",
            "user32.dll",
        ] {
            assert!(is_forbidden(name), "{name}");
        }
        for name in [
            "api-ms-win-core-comm-l1-1-0.dll",
            "api-ms-win-core-synch-l1-2-0.dll",
            "api-ms-win-crt-runtime-l1-1-0.dll",
            "ws2_32.dll",
            "kernel32.dll",
            "ntdll.dll",
            "bcrypt.dll",
        ] {
            assert!(!is_forbidden(name), "{name}");
        }
    }

    #[test]
    fn refuses_what_is_not_a_readable_pe() {
        assert!(imports(b"").is_err());
        assert!(imports(b"\x7fELF").is_err());
        let b = synthetic(&["kernel32.dll"], &[]);
        assert!(imports(&b[..0x80]).is_err(), "truncated headers");
        // The import directory points outside the sections.
        let mut outside = b.clone();
        let opt = 68 + 20;
        let at = opt + 112 + IMPORT * 8;
        outside[at..at + 4].copy_from_slice(&0x9000u32.to_le_bytes());
        assert!(imports(&outside).is_err());
        // A name without its terminating NUL inside the file.
        let mut unterminated = synthetic(&["kernel32.dll"], &[]);
        let len = unterminated.len();
        unterminated[0x400..len].fill(b'a');
        assert!(imports(&unterminated).is_err());
    }

    #[test]
    fn never_panics_on_corrupted_input() {
        let b = synthetic(&["kernel32.dll", "user32.dll"], &["oleaut32.dll"]);
        // Every byte of the headers and directories, flipped in turn.
        for i in 0..0x400 {
            let mut c = b.clone();
            c[i] ^= 0xff;
            let _ = imports(&c);
            let mut c = b.clone();
            c.truncate(i);
            let _ = imports(&c);
        }
    }
}
