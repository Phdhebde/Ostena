//! Replays the cargo-fuzz corpus (`fuzz/corpus/login_messages`) on the
//! stable toolchain: every seed goes through the fuzzing entry point, and
//! the seeds of real messages must parse.

use std::path::PathBuf;

use ostena_common::api::login::{ErrorResponse, LoginRequest, LoginResponse, LogoutRequest};

fn corpus() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fuzz/corpus/login_messages")
}

#[test]
fn replay_login_messages_corpus() {
    let mut seen = 0;
    for entry in std::fs::read_dir(corpus()).expect("corpus directory must exist") {
        let path = entry.unwrap().path();
        let data = std::fs::read(&path).unwrap();
        ostena_common::api::login::fuzz(&data);
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        let parsed = match name.as_str() {
            "seed-login-request.json" => LoginRequest::parse(&data).is_ok(),
            "seed-login-response.json" => LoginResponse::parse(&data).is_ok(),
            "seed-error.json" => ErrorResponse::parse(&data).is_ok(),
            "seed-logout.json" => LogoutRequest::parse(&data).is_ok(),
            _ => true,
        };
        assert!(parsed, "{name} must parse");
        seen += 1;
    }
    assert!(seen >= 4);
}
