//! ostena-tunnel: the TCP multiplexer fed with arbitrary frames, as a
//! hostile peer would send them (decoder and connection state).

#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    ostena_tunnel::fuzz::mux(data);
});
