//! ostena-rdp: X.224 Connection Confirm and the guard on arbitrary input.

#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    ostena_rdp::fuzz::x224(data);
});
