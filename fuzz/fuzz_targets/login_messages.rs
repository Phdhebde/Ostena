//! ostena-common: the login API messages on arbitrary input. What is
//! accepted must serialise and parse back to the same value.

#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    ostena_common::api::login::fuzz(data);
});
