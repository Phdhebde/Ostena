//! ostena-ssh: the OpenSSH certificate codec on arbitrary input. Whatever
//! parses must encode back byte for byte, and the user and host policies
//! must not panic.

#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    ostena_ssh::fuzz::certificate(data);
});
