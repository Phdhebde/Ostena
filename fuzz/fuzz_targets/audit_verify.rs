//! Full verification of an arbitrary audit export, with the harness key
//! trusted.

#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    ostena_audit::fuzz::verify(data);
});
