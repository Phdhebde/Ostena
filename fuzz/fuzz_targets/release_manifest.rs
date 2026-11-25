//! Release manifest and signature decoders on arbitrary input (canonical
//! round trips), and verification against the harness key (ADR-0017).

#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    ostena_crypto::release::fuzz::decode(data);
});
