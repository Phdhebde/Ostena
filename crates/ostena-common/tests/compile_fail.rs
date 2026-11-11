//! Compile-time proof that a `Secret` cannot be formatted, converted to a
//! `String`, recorded as a `tracing` field, cloned, or held by a type deriving
//! `Debug`. Expected compiler output is in `tests/ui/*.stderr`; regenerate it
//! with `TRYBUILD=overwrite cargo test -p ostena-common --test compile_fail`
//! after a toolchain update, and review the diff.

#[test]
fn secret_misuse_does_not_compile() {
    let cases = trybuild::TestCases::new();
    cases.compile_fail("tests/ui/*.rs");
}
