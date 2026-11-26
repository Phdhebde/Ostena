//! ostena-ldap: LDAP messages (responses read by the client, requests read
//! by the test directory) on arbitrary input. Must never panic.

#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    ostena_ldap::fuzz::messages(data);
});
