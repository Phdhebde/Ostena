//! The `OpenAPI` document of the portal API against the route table and the
//! Rust types (ADR-0020): every route is described with the same method,
//! authentication, role and fresh authentication, nothing else is
//! described, and every example of every schema goes through the strict
//! Rust type and encodes back to the same JSON.

#![allow(clippy::unwrap_used, clippy::panic, reason = "test")]

use std::collections::BTreeSet;

use ostena_common::api::web::{
    AccessGrant, AccessProtocol, AccessRequest, Channel, ErrorBody, LoginSessionItem,
    LoginSessionList, ReauthenticateRequest, RevokeRequest, Role, SessionInfo, SessionRequest,
};
use ostena_core::web::OPENAPI;
use ostena_core::web::routes::{Access, ROUTES};
use serde_json::Value;

fn document() -> Value {
    serde_json::from_str(OPENAPI).unwrap()
}

const METHODS: [&str; 8] = [
    "get", "put", "post", "delete", "options", "head", "patch", "trace",
];

#[test]
fn every_route_is_described_and_nothing_else() {
    let doc = document();
    assert_eq!(doc["openapi"], "3.1.0");
    // The default: a session.
    assert_eq!(doc["security"], serde_json::json!([{ "session": [] }]));
    let mut described = BTreeSet::new();
    for (path, item) in doc["paths"].as_object().unwrap() {
        for (method, _) in item.as_object().unwrap() {
            assert!(METHODS.contains(&method.as_str()), "{path}: {method}");
            described.insert((method.clone(), path.clone()));
        }
    }
    let routed: BTreeSet<_> = ROUTES
        .iter()
        .map(|r| (r.method.openapi().to_owned(), r.path.to_owned()))
        .collect();
    assert_eq!(described, routed);

    for route in ROUTES {
        let operation = &doc["paths"][route.path][route.method.openapi()];
        let at = format!("{} {}", route.method.openapi(), route.path);
        // Authentication: `security: []` exactly for the public routes.
        let public = operation.get("security") == Some(&serde_json::json!([]));
        assert_eq!(public, route.access == Access::Public, "{at}: security");
        if let Some(security) = operation.get("security") {
            assert!(
                security == &serde_json::json!([]),
                "{at}: only the default security or none"
            );
        }
        // Role.
        let role = operation.get("x-ostena-role").and_then(Value::as_str);
        let expected = match route.access {
            Access::Role(r) => Some(r.as_str()),
            _ => None,
        };
        assert_eq!(role, expected, "{at}: role");
        // Fresh authentication.
        let fresh = operation
            .get("x-ostena-fresh-authentication")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        assert_eq!(fresh, route.fresh, "{at}: fresh authentication");
        // Every route with a session can answer 401.
        if route.access != Access::Public {
            assert!(
                operation["responses"].get("401").is_some(),
                "{at}: no 401 described"
            );
        }
        // A path parameter is declared for each `{…}` segment.
        if route.path.contains("{id}") {
            let parameters = operation["parameters"].as_array().unwrap();
            assert!(
                parameters
                    .iter()
                    .any(|p| p["name"] == "id" && p["in"] == "path" && p["required"] == true),
                "{at}: parameter id"
            );
        }
    }
}

/// Parses `example` with the Rust type of schema `name` and encodes it
/// back.
fn round_trip(name: &str, example: &Value) -> Value {
    let bytes = serde_json::to_vec(example).unwrap();
    match name {
        "SessionRequest" => {
            let parsed = SessionRequest::parse(&bytes).unwrap();
            serde_json::to_value(&parsed).unwrap()
        }
        "ReauthenticateRequest" => {
            let parsed = ReauthenticateRequest::parse(&bytes).unwrap();
            serde_json::to_value(&parsed).unwrap()
        }
        "SessionInfo" => serde_json::to_value(SessionInfo::parse(&bytes).unwrap()).unwrap(),
        "LoginSessionList" => {
            serde_json::to_value(LoginSessionList::parse(&bytes).unwrap()).unwrap()
        }
        "LoginSessionItem" => {
            let item: LoginSessionItem = serde_json::from_slice(&bytes).unwrap();
            // Checked as a list of one.
            LoginSessionList::parse(
                &serde_json::to_vec(&LoginSessionList {
                    sessions: vec![item.clone()],
                })
                .unwrap(),
            )
            .unwrap();
            serde_json::to_value(item).unwrap()
        }
        "RevokeRequest" => serde_json::to_value(RevokeRequest::parse(&bytes).unwrap()).unwrap(),
        "Error" => serde_json::to_value(ErrorBody::parse(&bytes).unwrap()).unwrap(),
        "AccessRequest" => serde_json::to_value(AccessRequest::parse(&bytes).unwrap()).unwrap(),
        "AccessGrant" => serde_json::to_value(AccessGrant::parse(&bytes).unwrap()).unwrap(),
        "AccessProtocol" => {
            serde_json::to_value(serde_json::from_slice::<AccessProtocol>(&bytes).unwrap()).unwrap()
        }
        "Role" => serde_json::to_value(serde_json::from_slice::<Role>(&bytes).unwrap()).unwrap(),
        "Channel" => {
            serde_json::to_value(serde_json::from_slice::<Channel>(&bytes).unwrap()).unwrap()
        }
        "Uuid" => {
            let text: String = serde_json::from_slice(&bytes).unwrap();
            assert!(ostena_common::api::login::is_uuid(&text), "{text}");
            Value::String(text)
        }
        "Username" => {
            let text: String = serde_json::from_slice(&bytes).unwrap();
            assert!(ostena_common::api::login::is_username(&text), "{text}");
            Value::String(text)
        }
        other => panic!("schema {other} has no Rust type in this test"),
    }
}

#[test]
fn every_example_goes_through_its_rust_type() {
    let doc = document();
    let schemas = doc["components"]["schemas"].as_object().unwrap();
    assert!(!schemas.is_empty());
    for (name, schema) in schemas {
        let examples = schema["examples"]
            .as_array()
            .unwrap_or_else(|| panic!("{name}: no examples"));
        assert!(!examples.is_empty(), "{name}: no examples");
        for example in examples {
            assert_eq!(&round_trip(name, example), example, "{name}");
        }
        // Objects are closed, as the Rust types (deny_unknown_fields).
        if schema["type"] == "object" {
            assert_eq!(schema["additionalProperties"], false, "{name}");
            let required: BTreeSet<_> = schema["required"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| v.as_str().unwrap())
                .collect();
            let properties: BTreeSet<_> = schema["properties"]
                .as_object()
                .unwrap()
                .keys()
                .map(String::as_str)
                .collect();
            assert_eq!(required, properties, "{name}: every field is required");
        }
    }
    // An unknown field is refused by the types the examples went through.
    assert!(
        SessionRequest::parse(br#"{"username":"a","password":"p","totp":"1","extra":1}"#).is_err()
    );
}

#[test]
fn every_reference_resolves() {
    let doc = document();
    let mut stack = vec![&doc];
    let mut seen = 0;
    while let Some(value) = stack.pop() {
        match value {
            Value::Object(map) => {
                if let Some(Value::String(target)) = map.get("$ref") {
                    let pointer = target.strip_prefix('#').unwrap();
                    assert!(doc.pointer(pointer).is_some(), "{target}");
                    seen += 1;
                }
                stack.extend(map.values());
            }
            Value::Array(items) => stack.extend(items.iter()),
            _ => {}
        }
    }
    assert!(seen > 10);
}
