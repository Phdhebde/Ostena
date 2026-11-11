//! Scope policy parsing and compilation on arbitrary input.

#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    ostena_scope::fuzz::policy(data);
});
