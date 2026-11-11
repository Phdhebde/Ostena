//! Grant decoders on arbitrary input: binary, text and full verification.

#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    ostena_grant::fuzz::decode(data);
});
