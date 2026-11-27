#![allow(clippy::unwrap_used, reason = "test")]

use ostena_frame::{
    CURRENT_VERSION, Code, Direction, Flags, Outgoing, Payload, Sender, decode_message,
};
use proptest::prelude::*;

use super::*;

/// The gateway end, with the same crate.
struct Gateway {
    sender: Sender,
    receiver: Receiver,
}

impl Gateway {
    fn new() -> Self {
        Self {
            sender: Sender::new(Direction::ToBrowser),
            receiver: Receiver::new(),
        }
    }

    fn take(&mut self, message: &[u8]) -> Payload<'static> {
        let frame = decode_message(message, Direction::ToGateway).unwrap();
        self.receiver.accept(&frame).unwrap();
        match frame.payload {
            Payload::Hello { versions, .. } => Payload::Hello {
                versions,
                capabilities: 0,
            },
            Payload::Ping { token } => Payload::Ping { token },
            other => panic!("unexpected {other:?}"),
        }
    }

    fn send(&mut self, payload: &Payload<'_>) -> Vec<u8> {
        let frame = Outgoing::new(payload, Direction::ToBrowser, 0, Flags::NONE).unwrap();
        let mut out = Vec::new();
        self.sender.encode(&frame, &mut out).unwrap();
        out
    }
}

#[test]
fn negotiates_then_pings() {
    let mut client = Session::new();
    let mut gateway = Gateway::new();
    // Nothing but the Hello can leave before the negotiation.
    assert_eq!(client.ping(1).unwrap_err().code, Code::NotNegotiated);
    client.hello().unwrap();
    assert_eq!(client.version(), 0);
    let hello = client.next_frame().unwrap().unwrap();
    let Payload::Hello { versions, .. } = gateway.take(&hello) else {
        unreachable!()
    };
    assert_eq!(versions, SUPPORTED_VERSIONS);
    let ack = gateway.send(&Payload::HelloAck {
        version: CURRENT_VERSION,
        capabilities: 0,
    });
    gateway.sender.set_version(CURRENT_VERSION);
    gateway.receiver.set_version(CURRENT_VERSION);
    let received = client.receive(&ack).unwrap();
    assert_eq!(received.frame_type, FrameType::HelloAck as u8);
    assert_eq!(client.version(), CURRENT_VERSION);
    client.ping(1).unwrap();
    let ping_frame = client.next_frame().unwrap().unwrap();
    assert_eq!(gateway.take(&ping_frame), Payload::Ping { token: 1 });
    assert_eq!(client.next_frame().unwrap(), None);
    let pong = gateway.send(&Payload::Pong { token: 1 });
    assert_eq!(
        client.receive(&pong).unwrap(),
        Received {
            frame_type: pong_type(),
            token: 1
        }
    );
    // A frame seen twice breaks the sequence.
    assert_eq!(client.receive(&pong).unwrap_err().code, Code::Sequence);
}

#[test]
fn refuses_what_the_gateway_must_not_send() {
    let mut gateway = Gateway::new();
    // A Pong before the negotiation.
    let mut early = Gateway::new();
    early.sender.set_version(CURRENT_VERSION);
    let pong = early.send(&Payload::Pong { token: 7 });
    assert_eq!(
        Session::new().receive(&pong).unwrap_err().code,
        Code::NotNegotiated
    );
    // A frame of the browser direction.
    let mut client = Session::new();
    client.hello().unwrap();
    let hello = client.next_frame().unwrap().unwrap();
    assert!(Session::new().receive(&hello).is_err());
    // Truncated.
    let ack = gateway.send(&Payload::HelloAck {
        version: CURRENT_VERSION,
        capabilities: 0,
    });
    assert!(Session::new().receive(&ack[..ack.len() - 1]).is_err());
    assert_eq!(frame_version(), CURRENT_VERSION);
}

proptest! {
    #[test]
    fn any_message_is_refused_or_accepted_without_panic(
        messages in proptest::collection::vec(proptest::collection::vec(any::<u8>(), 0..64), 0..8)
    ) {
        let mut client = Session::new();
        for m in &messages {
            let _ = client.receive(m);
        }
        prop_assert!(client.version() <= CURRENT_VERSION);
    }
}
