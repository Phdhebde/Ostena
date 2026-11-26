//! ostena-rdp: MCS Connect Response, GCC blocks and the Connect Initial guard on arbitrary input.

#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    ostena_rdp::fuzz::mcs_gcc(data);
});
