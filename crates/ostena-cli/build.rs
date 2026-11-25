//! Link options of the `ostena` binary.
//!
//! Windows (MSVC): `oleaut32.dll` is loaded on first use only
//! (`/DELAYLOAD`, ADR-0009). The SSH library imports two of its functions
//! (BSTR strings, through the client of the SSH agent of the user), which
//! the agent never calls: imported statically, the DLL and the COM runtime
//! it pulls in (`combase.dll`, `msvcp_win.dll`) would be loaded into the
//! service at startup, as memory and as attack surface. `cargo xtask
//! check-release` checks that no GUI or COM DLL is imported statically, and
//! `cargo xtask footprint` that none is loaded at rest.
//!
//! Set here rather than in `.cargo/config.toml`: it applies to this binary
//! only, not to the test binaries nor to the other crates, and to any
//! `cargo build` of it.

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    let windows = std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows");
    let msvc = std::env::var("CARGO_CFG_TARGET_ENV").as_deref() == Ok("msvc");
    let ssh = std::env::var_os("CARGO_FEATURE_SSH").is_some();
    if windows && msvc && ssh {
        println!("cargo:rustc-link-arg-bin=ostena=/DELAYLOAD:oleaut32.dll");
        println!("cargo:rustc-link-arg-bin=ostena=delayimp.lib");
    }
}
