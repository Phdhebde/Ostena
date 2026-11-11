//! ostena-tunnel: control message and channel header decoding on arbitrary
//! input (messages from the peer are untrusted).

#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    ostena_tunnel::fuzz::decode(data);
});
