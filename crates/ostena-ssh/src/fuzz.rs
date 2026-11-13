//! Entry points for `cargo fuzz` (the `fuzz/` workspace).

use crate::precheck::{Role, inspect};

/// The pre-check on arbitrary peer bytes, in both roles: never panics.
pub fn precheck(data: &[u8]) {
    let _ = inspect(data, Role::Server);
    let _ = inspect(data, Role::Client);
}
