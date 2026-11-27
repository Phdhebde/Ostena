//! Protocol core of the browser client (ADR-0020, § 4): the encoding,
//! decoding, version negotiation, sequence checks and priority scheduling of
//! `ostena-frame`, compiled to WebAssembly for the portal. The same code as
//! on the gateway, so the two ends cannot diverge (ADR-0006).
//!
//! [`Session`] is plain Rust, tested natively; [`Client`] is its binding to
//! JavaScript through wasm-bindgen (no `js-sys`, no `web-sys`). The portal
//! owns the WebSocket: it hands every received message to
//! [`Client::receive`], and sends what [`Client::next_frame`] gives while
//! `WebSocket.bufferedAmount` is below its threshold, so that a frame handed
//! to the browser can never be overtaken (inputs before display).

#![forbid(unsafe_code)]

use ostena_frame::{
    Code, Direction, Flags, FrameError, FrameType, Limits, Outgoing, Payload, Receiver,
    SUPPORTED_VERSIONS, Scheduler, Sender, decode_message,
};
use wasm_bindgen::prelude::wasm_bindgen;

/// The browser end of one gateway session.
#[derive(Debug)]
pub struct Session {
    scheduler: Scheduler,
    sender: Sender,
    receiver: Receiver,
}

impl Default for Session {
    fn default() -> Self {
        Self::new()
    }
}

/// What a received frame was, for the portal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Received {
    /// The frame type code.
    pub frame_type: u8,
    /// The token of a `Pong`, 0 otherwise.
    pub token: u64,
}

impl Session {
    /// A session before negotiation.
    pub fn new() -> Self {
        Self {
            scheduler: Scheduler::new(Limits::default()),
            sender: Sender::new(Direction::ToGateway),
            receiver: Receiver::new(),
        }
    }

    fn push(&mut self, payload: &Payload<'_>) -> Result<(), FrameError> {
        let frame = Outgoing::new(payload, Direction::ToGateway, 0, Flags::NONE)?;
        self.scheduler.push(frame)
    }

    /// Queues the `Hello`: every version this client supports.
    ///
    /// # Errors
    ///
    /// The scheduler is full (`FRM-E012`).
    pub fn hello(&mut self) -> Result<(), FrameError> {
        self.push(&Payload::Hello {
            versions: SUPPORTED_VERSIONS,
            capabilities: 0,
        })
    }

    /// Queues a `Ping` with `token`, once the version is negotiated (a
    /// frame popped before it could not be sent).
    ///
    /// # Errors
    ///
    /// Before the `HelloAck` (`FRM-E013`); the scheduler is full
    /// (`FRM-E012`).
    pub fn ping(&mut self, token: u64) -> Result<(), FrameError> {
        if self.receiver.version().is_none() {
            return Err(FrameError {
                code: Code::NotNegotiated,
                reason: "Ping avant la négociation",
            });
        }
        self.push(&Payload::Ping { token })
    }

    /// The next frame to send, highest priority first, with its sequence
    /// number; `None` when nothing waits.
    ///
    /// # Errors
    ///
    /// A frame other than `Hello` before the negotiation (`FRM-E013`).
    pub fn next_frame(&mut self) -> Result<Option<Vec<u8>>, FrameError> {
        let Some(frame) = self.scheduler.pop() else {
            return Ok(None);
        };
        let mut out = Vec::with_capacity(frame.wire_len());
        self.sender.encode(&frame, &mut out)?;
        Ok(Some(out))
    }

    /// Checks one message from the gateway: one whole frame, in order, of
    /// the negotiated version. The `HelloAck` sets the version.
    ///
    /// # Errors
    ///
    /// The frame is refused: the session must be closed.
    pub fn receive(&mut self, message: &[u8]) -> Result<Received, FrameError> {
        let frame = decode_message(message, Direction::ToBrowser)?;
        self.receiver.accept(&frame)?;
        if let Some(version) = self.receiver.version() {
            self.sender.set_version(version);
        }
        let token = match frame.payload {
            Payload::Pong { token } => token,
            _ => 0,
        };
        Ok(Received {
            frame_type: frame.header.frame_type as u8,
            token,
        })
    }

    /// The negotiated version, 0 before the `HelloAck`.
    pub fn version(&self) -> u8 {
        self.receiver.version().unwrap_or(0)
    }
}

/// The highest version of `ostena-frame` this client speaks.
#[wasm_bindgen(js_name = frameVersion)]
pub fn frame_version() -> u8 {
    ostena_frame::CURRENT_VERSION
}

/// The code of the `Pong` frame type, to recognise it in JavaScript.
#[wasm_bindgen(js_name = pongType)]
pub fn pong_type() -> u8 {
    FrameType::Pong as u8
}

/// The binding of [`Session`] to JavaScript. Methods that can fail return
/// the stable code of the refusal (`FRM-E0xx`) as their error.
#[wasm_bindgen]
#[derive(Debug, Default)]
pub struct Client {
    session: Session,
    last_token: u64,
}

fn code(e: FrameError) -> String {
    let code: Code = e.code;
    code.as_str().to_owned()
}

#[wasm_bindgen]
impl Client {
    /// A client before negotiation.
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        Self::default()
    }

    /// Queues the `Hello`.
    ///
    /// # Errors
    ///
    /// The refusal code.
    pub fn hello(&mut self) -> Result<(), String> {
        self.session.hello().map_err(code)
    }

    /// Queues a `Ping`.
    ///
    /// # Errors
    ///
    /// The refusal code.
    pub fn ping(&mut self, token: u64) -> Result<(), String> {
        self.session.ping(token).map_err(code)
    }

    /// The next frame to send, or `undefined`.
    ///
    /// # Errors
    ///
    /// The refusal code.
    #[wasm_bindgen(js_name = nextFrame)]
    pub fn next_frame(&mut self) -> Result<Option<Vec<u8>>, String> {
        self.session.next_frame().map_err(code)
    }

    /// Checks a message from the gateway; returns its frame type code.
    ///
    /// # Errors
    ///
    /// The refusal code: the portal closes the session.
    pub fn receive(&mut self, message: &[u8]) -> Result<u8, String> {
        let received = self.session.receive(message).map_err(code)?;
        self.last_token = received.token;
        Ok(received.frame_type)
    }

    /// The token of the last `Pong` received.
    #[wasm_bindgen(js_name = lastToken)]
    pub fn last_token(&self) -> u64 {
        self.last_token
    }

    /// The negotiated version, 0 before the `HelloAck`.
    pub fn version(&self) -> u8 {
        self.session.version()
    }
}

#[cfg(test)]
mod tests;
