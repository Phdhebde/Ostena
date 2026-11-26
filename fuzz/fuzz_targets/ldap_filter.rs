//! ostena-ldap: search filters in text form (RFC 4515), from the
//! configuration. What parses must survive an encoding round trip.

#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    ostena_ldap::fuzz::filter(data);
});
