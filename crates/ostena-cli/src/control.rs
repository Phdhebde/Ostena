//! Control plane protocol (ADR-0007): one JSON request, one JSON answer.
//! Read-only commands only: `status`, `version`, `config_fingerprint`. A
//! command that changes the agent state will require local authentication.

use std::sync::Arc;
use std::time::Instant;

use ostena_platform::PlatformError;
use ostena_platform::control::{
    ControlListener, ExpectedServer, connect, read_message, write_message,
};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::sessions::Sessions;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    command: String,
}

/// What the control plane reports.
pub(crate) struct AgentInfo {
    pub started: Instant,
    pub gateway_group: String,
    pub config_fingerprint: String,
    pub sessions: Arc<Sessions>,
    /// The link to the core, once started.
    pub link: std::sync::OnceLock<Arc<ostena_tunnel::link::AgentLink>>,
    /// What the core pushed, once the link is started.
    pub gateway: std::sync::OnceLock<ostena_tunnel::gateway::Gateway>,
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Answer to one request (never fails: errors are answers too).
pub(crate) fn answer(info: &AgentInfo, request: &[u8]) -> Value {
    let Ok(request) = serde_json::from_slice::<Request>(request) else {
        return json!({ "error": "requête invalide" });
    };
    match request.command.as_str() {
        "status" => json!({
            "state": "running",
            "version": ostena_common::VERSION,
            "uptime_secs": info.started.elapsed().as_secs(),
            "gateway_group": info.gateway_group,
            "core": info.link.get().map_or_else(
                || "lien désactivé (configuration)".to_owned(),
                |l| l.status().summary(unix_now()),
            ),
            "core_link": info.link.get().map(|l| l.status()),
            "pushes": info.gateway.get().map(|g| g.state().versions()),
            "sessions": info.sessions.active(),
            "resident_bytes": ostena_platform::memory::resident_bytes(),
            "config_fingerprint": info.config_fingerprint,
        }),
        "version" => json!({ "version": ostena_common::VERSION }),
        "config_fingerprint" => json!({ "config_fingerprint": info.config_fingerprint }),
        _ => {
            json!({ "error": "commande inconnue (lecture seule : status, version, config_fingerprint)" })
        }
    }
}

/// Serves the control plane until the task is aborted.
pub(crate) async fn serve(listener: Arc<ControlListener>, info: Arc<AgentInfo>) {
    loop {
        let mut stream = match listener.accept().await {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(event = "agent.control_error", code = e.code.as_str(), "{e}");
                continue;
            }
        };
        let info = Arc::clone(&info);
        tokio::spawn(async move {
            let result = async {
                let request = read_message(&mut *stream).await?;
                let reply = serde_json::to_vec(&answer(&info, &request)).unwrap_or_default();
                write_message(&mut *stream, &reply).await
            }
            .await;
            if let Err(e) = result {
                tracing::warn!(event = "agent.control_error", code = e.code.as_str(), "{e}");
            }
        });
    }
}

/// Sends `command` and returns the answer.
///
/// # Errors
///
/// `AGT-E006`–`E009` from the transport, or an unreadable answer (`AGT-E008`).
pub(crate) async fn query(
    endpoint: &str,
    expected: ExpectedServer,
    command: &str,
) -> Result<Value, PlatformError> {
    let mut stream = connect(endpoint, expected).await?;
    let request = serde_json::to_vec(&json!({ "command": command })).unwrap_or_default();
    write_message(&mut *stream, &request).await?;
    let reply = read_message(&mut *stream).await?;
    serde_json::from_slice(&reply).map_err(|e| {
        PlatformError::new(
            ostena_platform::Code::ControlIo,
            format!("réponse illisible : {e}"),
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn info() -> AgentInfo {
        AgentInfo {
            started: Instant::now(),
            gateway_group: "2f6c9a4e-1b2c-4d5e-8f90-a1b2c3d4e5f6".into(),
            config_fingerprint: "sha256:abcd".into(),
            sessions: Arc::new(Sessions::new()),
            link: std::sync::OnceLock::new(),
            gateway: std::sync::OnceLock::new(),
        }
    }

    #[test]
    fn read_only_commands() {
        let i = info();
        let status = answer(&i, br#"{"command":"status"}"#);
        assert_eq!(status["state"], "running");
        assert_eq!(status["sessions"], 0);
        assert_eq!(status["config_fingerprint"], "sha256:abcd");
        assert_eq!(
            answer(&i, br#"{"command":"version"}"#)["version"],
            ostena_common::VERSION
        );
        assert_eq!(
            answer(&i, br#"{"command":"config_fingerprint"}"#)["config_fingerprint"],
            "sha256:abcd"
        );
    }

    #[test]
    fn anything_else_is_refused() {
        let i = info();
        for request in [
            &br#"{"command":"stop"}"#[..],
            br#"{"command":"status","x":1}"#,
            b"not json",
            b"",
        ] {
            assert!(
                answer(&i, request)["error"].is_string(),
                "{}",
                String::from_utf8_lossy(request)
            );
        }
    }
}
