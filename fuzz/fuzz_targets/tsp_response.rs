//! RFC 3161 responses and tokens on arbitrary input: strict DER, the CMS
//! profile, then the signature and certificate checks of a token verified
//! against its own certificates (ADR-0012).

#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    ostena_crypto::tsp::fuzz::response(data);
});
