//! ostena-frame: reassembly on arbitrary input.

#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    ostena_frame::fuzz::reassembly(data);
});
