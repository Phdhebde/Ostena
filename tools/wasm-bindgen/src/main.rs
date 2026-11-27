//! `ostena-wasm-bindgen INPUT.wasm OUT_DIR`: writes the JavaScript glue of
//! `ostena-web-client` for an ES module (`--target web`), with its
//! TypeScript declarations (for the type check of the portal, never
//! shipped), without names or producers sections, so that the output
//! depends on the input only (ADR-0020).

#![forbid(unsafe_code)]

use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [input, out_dir] = args.as_slice() else {
        let _ = std::io::Write::write_all(
            &mut std::io::stderr(),
            b"usage: ostena-wasm-bindgen INPUT.wasm OUT_DIR\n",
        );
        return ExitCode::from(2);
    };
    let mut bindgen = wasm_bindgen_cli_support::Bindgen::new();
    let result = bindgen.input_path(input).web(true).and_then(|b| {
        b.typescript(true)
            .debug(false)
            .keep_debug(false)
            .remove_name_section(true)
            .remove_producers_section(true)
            .out_name("ostena_web_client")
            .generate(out_dir)
    });
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            let _ = std::io::Write::write_all(
                &mut std::io::stderr(),
                format!("ostena-wasm-bindgen: {e:#}\n").as_bytes(),
            );
            ExitCode::FAILURE
        }
    }
}
