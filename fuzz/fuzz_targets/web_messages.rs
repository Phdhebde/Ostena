//! ostena-common: the messages of the portal REST API on arbitrary input.
//! What is accepted must serialise and parse back to the same value.

#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    ostena_common::api::web::fuzz(data);
});
