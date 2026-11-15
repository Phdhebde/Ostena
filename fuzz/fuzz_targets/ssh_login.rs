//! ostena-ssh: the `account@resource` user name on arbitrary input. What is
//! accepted must rebuild the input.

#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    ostena_ssh::fuzz::login(data);
});
