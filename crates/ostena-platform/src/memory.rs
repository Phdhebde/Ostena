//! Resident memory of the current process, for the footprint (ADR-0007).

/// Resident set size in bytes (`VmRSS` on Linux, working set on Windows).
pub fn resident_bytes() -> Option<u64> {
    imp::resident_bytes()
}

#[cfg(target_os = "linux")]
mod imp {
    pub(super) fn resident_bytes() -> Option<u64> {
        let status = std::fs::read_to_string("/proc/self/status").ok()?;
        let kib: u64 = status
            .lines()
            .find_map(|l| l.strip_prefix("VmRSS:"))?
            .trim()
            .trim_end_matches("kB")
            .trim()
            .parse()
            .ok()?;
        kib.checked_mul(1024)
    }
}

#[cfg(windows)]
#[allow(unsafe_code, reason = "GetProcessMemoryInfo; documented and tested")]
mod imp {
    use windows_sys::Win32::System::ProcessStatus::{
        GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS,
    };
    use windows_sys::Win32::System::Threading::GetCurrentProcess;

    pub(super) fn resident_bytes() -> Option<u64> {
        // SAFETY: PROCESS_MEMORY_COUNTERS is plain data; zero is a valid value.
        let mut counters: PROCESS_MEMORY_COUNTERS = unsafe { std::mem::zeroed() };
        let size = u32::try_from(size_of::<PROCESS_MEMORY_COUNTERS>()).ok()?;
        counters.cb = size;
        // SAFETY: the pseudo-handle of the current process is always valid;
        // `counters` is a valid out-buffer of `size` bytes.
        let ok = unsafe { GetProcessMemoryInfo(GetCurrentProcess(), &raw mut counters, size) };
        (ok != 0).then_some(counters.WorkingSetSize as u64)
    }
}

#[cfg(not(any(target_os = "linux", windows)))]
mod imp {
    pub(super) fn resident_bytes() -> Option<u64> {
        None
    }
}

#[cfg(test)]
mod tests {
    #[test]
    #[cfg(any(target_os = "linux", windows))]
    fn reports_a_plausible_size() {
        let bytes = super::resident_bytes().unwrap();
        // More than 100 KiB and less than 4 GiB for a test process.
        assert!((100 * 1024..4 << 30).contains(&bytes), "{bytes}");
    }
}
