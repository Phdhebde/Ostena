//! ostena-rdp: SMB 2 NEGOTIATE response of the signing probe on arbitrary input.

#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    ostena_rdp::fuzz::smb_negotiate(data);
});
