//! Target parsing, IPv6 normalisation and scope decision on arbitrary input.

#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    ostena_scope::fuzz::target(data);
});
