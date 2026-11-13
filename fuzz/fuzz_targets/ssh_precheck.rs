//! ostena-ssh: pre-check of the SSH peer (identification line and first
//! KEXINIT) on arbitrary input, in both roles.

#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    ostena_ssh::fuzz::precheck(data);
});
