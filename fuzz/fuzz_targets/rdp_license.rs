//! ostena-rdp: licensing PDUs on arbitrary input.

#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    ostena_rdp::fuzz::license(data);
});
