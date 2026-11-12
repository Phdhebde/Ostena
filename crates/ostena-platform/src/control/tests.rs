use tokio::io::AsyncWriteExt;

use super::*;

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}

#[cfg(windows)]
fn endpoint(name: &str) -> String {
    format!(r"\\.\pipe\ostena-test-{}-{name}", std::process::id())
}

#[cfg(unix)]
fn endpoint(name: &str) -> String {
    let dir = std::env::temp_dir().join(format!("ostena-ctl-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    dir.join("agent.sock").display().to_string()
}

/// One request and its answer between an in-process server and client.
#[test]
fn request_and_answer() {
    runtime().block_on(async {
        let name = endpoint("roundtrip");
        let listener = std::sync::Arc::new(ControlListener::bind(&name).unwrap());
        let server = tokio::spawn({
            let listener = std::sync::Arc::clone(&listener);
            async move {
                let mut s = listener.accept().await.unwrap();
                let request = read_message(&mut *s).await.unwrap();
                write_message(&mut *s, &[request.as_slice(), b"+ok"].concat())
                    .await
                    .unwrap();
            }
        });
        let mut c = connect(&name, ExpectedServer::Process(std::process::id()))
            .await
            .unwrap();
        write_message(&mut *c, b"status").await.unwrap();
        let answer = read_message(&mut *c).await.unwrap();
        server.await.unwrap();
        assert_eq!(answer, b"status+ok");
    });
}

#[test]
fn a_taken_name_refuses_to_start() {
    runtime().block_on(async {
        let name = endpoint("squat");
        let _first = ControlListener::bind(&name).unwrap();
        let err = ControlListener::bind(&name).unwrap_err();
        assert_eq!(err.code, Code::ControlNameTaken, "{err}");
    });
}

#[test]
fn oversized_messages_are_refused() {
    runtime().block_on(async {
        let name = endpoint("oversize");
        let listener = std::sync::Arc::new(ControlListener::bind(&name).unwrap());
        let server = tokio::spawn({
            let listener = std::sync::Arc::clone(&listener);
            async move {
                let mut s = listener.accept().await.unwrap();
                read_message(&mut *s).await.map(|_| ())
            }
        });
        let mut c = connect(&name, ExpectedServer::Process(std::process::id()))
            .await
            .unwrap();
        assert_eq!(
            write_message(&mut *c, &[0; MAX_MESSAGE + 1])
                .await
                .unwrap_err()
                .code,
            Code::ControlIo
        );
        // A raw oversized length is refused by the reader.
        c.write_all(&(u32::try_from(MAX_MESSAGE).unwrap() + 1).to_be_bytes())
            .await
            .unwrap();
        c.flush().await.unwrap();
        assert_eq!(server.await.unwrap().unwrap_err().code, Code::ControlIo);
    });
}

#[cfg(windows)]
#[test]
fn another_server_process_is_not_trusted() {
    runtime().block_on(async {
        let name = endpoint("identity");
        let listener = std::sync::Arc::new(ControlListener::bind(&name).unwrap());
        let accept = tokio::spawn({
            let listener = std::sync::Arc::clone(&listener);
            async move { listener.accept().await.map(|_| ()) }
        });
        let result = connect(&name, ExpectedServer::Process(std::process::id() + 1))
            .await
            .map(|_| ());
        assert_eq!(result.unwrap_err().code, Code::ControlNotAuthentic);
        let _ = accept.await;
    });
}

#[cfg(windows)]
#[test]
fn pipe_dacl_is_restricted() {
    let sddl = sddl();
    assert!(
        sddl.starts_with("D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;OW)"),
        "{sddl}"
    );
    assert!(!sddl.contains(";WD)") && !sddl.contains(";AU)") && !sddl.contains(";BU)"));
    // The SDDL converts (exercises the descriptor FFI and its release).
    assert!(Descriptor::from_sddl(&sddl).is_ok());
    assert!(Descriptor::from_sddl("not sddl").is_err());
}

#[cfg(unix)]
#[test]
fn stale_socket_is_replaced_and_files_are_private() {
    use std::os::unix::fs::PermissionsExt;
    runtime().block_on(async {
        let name = endpoint("stale");
        drop(ControlListener::bind(&name).unwrap()); // removes its socket on drop
        // Leave a stale socket file behind: bind a std listener and drop it.
        let path = std::path::Path::new(&name);
        drop(std::os::unix::net::UnixListener::bind(path).unwrap());
        assert!(path.exists());
        let listener = ControlListener::bind(&name).unwrap();
        let mode = std::fs::metadata(path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        let dir_mode = std::fs::metadata(path.parent().unwrap())
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(dir_mode, 0o700);
        drop(listener);
    });
}

#[cfg(unix)]
#[test]
fn an_open_directory_is_refused() {
    use std::os::unix::fs::PermissionsExt;
    let name = endpoint("open-dir");
    let dir = std::path::Path::new(&name).parent().unwrap().to_path_buf();
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert_eq!(
        ControlListener::bind(&name).unwrap_err().code,
        Code::ControlNameTaken
    );
    runtime().block_on(async {
        assert!(connect(&name, ExpectedServer::Service).await.is_err());
    });
}
