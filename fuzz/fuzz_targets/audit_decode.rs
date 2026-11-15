//! Audit decoders on arbitrary input: record (canonical round trip), head
//! (binary and text) and export frames.

#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    ostena_audit::fuzz::decode(data);
});
