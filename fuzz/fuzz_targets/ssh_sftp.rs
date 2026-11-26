//! ostena-ssh: the SFTP observer and the transfer command classifier on
//! arbitrary input. The operations seen must not depend on how the stream
//! is cut, and each must be a valid transcript note.

#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    ostena_ssh::fuzz::sftp(data);
});
