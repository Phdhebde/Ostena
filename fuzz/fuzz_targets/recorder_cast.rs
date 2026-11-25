//! Transcript stream decoder then asciicast writer on arbitrary input: UTF-8
//! lines without control characters, seal hashing what was written.

#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    ostena_recorder::fuzz::cast(data);
});
