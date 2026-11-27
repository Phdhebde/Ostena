//! Syslog streams on arbitrary input: RFC 5425 octet-counted frames and
//! RFC 5424 headers, read whole and byte by byte (ADR-0012).

#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    ostena_audit::fuzz::syslog(data);
});
