//! ostena-ws: client frames and upgrade headers on arbitrary input.

#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    ostena_ws::fuzz::frame(data);
});
