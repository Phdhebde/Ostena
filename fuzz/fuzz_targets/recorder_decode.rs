//! Transcript stream decoder on arbitrary input, fed in chunks: outcome
//! independent of the chunking, canonical frames.

#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    ostena_recorder::fuzz::decode(data);
});
