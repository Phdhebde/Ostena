//! ostena-rdp: CredSSP TSRequest and Early User Authorization Result on arbitrary input.

#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    ostena_rdp::fuzz::ts_request(data);
});
