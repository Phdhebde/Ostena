// The protocol core of the gateway sessions, in WebAssembly (ADR-0020, § 4):
// ostena-web-client, the same Rust code as the gateway. Loaded on demand,
// after the login: the login page never downloads it.
import init, { Client, frameVersion } from "./wasm/ostena_web_client.js";
import wasmUrl from "./wasm/ostena_web_client_bg.wasm?url";

/** Loads the module and checks that it encodes a Hello; returns the
 *  version of ostena-frame it speaks. */
export async function loadClient(): Promise<number> {
  await init({ module_or_path: wasmUrl });
  const client = new Client();
  try {
    client.hello();
    const hello = client.nextFrame();
    if (hello === undefined || hello.length === 0) {
      throw new Error("Hello absent");
    }
  } finally {
    client.free();
  }
  return frameVersion();
}
