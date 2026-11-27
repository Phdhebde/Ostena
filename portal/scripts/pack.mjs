// Packs the output of `vite build` for the core (ADR-0020, § 1), with Node's
// own modules only:
// - refuses any absolute URL outside a closed list (no external request);
// - gathers the licences of the shipped packages into licenses.txt;
// - compresses each text file with brotli (quality 11), kept only when it
//   is smaller;
// - writes SHA256SUMS (every served file, brotli variants included, in the
//   format of sha256sum, sorted by path) and manifest.json (path, type,
//   size and SHA-256 of each file, the digest of SHA256SUMS, the budget).
//
// The output depends on the sources and the lockfile only: no date, no
// absolute path, a fixed order. `ostena core portal-manifest` prints the
// digest of the embedded SHA256SUMS, to compare with a rebuild.

import { createHash } from "node:crypto";
import {
  existsSync,
  readFileSync,
  readdirSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { join, relative, sep } from "node:path";
import { constants, brotliCompressSync } from "node:zlib";

const root = new URL("..", import.meta.url).pathname;
const dist = join(root, "dist");

/** Served types, by extension; any other extension fails the build. */
const TYPES = {
  html: "text/html; charset=utf-8",
  js: "text/javascript; charset=utf-8",
  css: "text/css; charset=utf-8",
  svg: "image/svg+xml",
  json: "application/json",
  txt: "text/plain; charset=utf-8",
  wasm: "application/wasm",
  woff2: "font/woff2",
};
/** Types already compressed: no brotli variant. */
const COMPRESSED = new Set(["woff2"]);

/** Absolute URLs allowed in the bundle: XML namespaces, and the error
 *  documentation links of Svelte, which are text in error messages only. */
const ALLOWED_URLS = [
  /^http:\/\/www\.w3\.org\/(2000\/svg|1999\/xlink|1999\/xhtml|1998\/Math\/MathML|XML\/1998\/namespace|2000\/xmlns\/)$/,
  /^https:\/\/svelte\.dev\/e\/[a-z0-9_]+$/,
];

function fail(message) {
  console.error(`pack: ${message}`);
  process.exit(1);
}

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function walk(dir) {
  const out = [];
  for (const name of readdirSync(dir).sort()) {
    const path = join(dir, name);
    if (statSync(path).isDirectory()) {
      out.push(...walk(path));
    } else {
      out.push(relative(dist, path).split(sep).join("/"));
    }
  }
  return out;
}

function extension(path) {
  const dot = path.lastIndexOf(".");
  return dot < 0 ? "" : path.slice(dot + 1);
}

// 1. What the login page loads: index.html, its blocking scripts, and the
//    entry chunk with its static imports, styles and assets (Vite manifest).
const viteManifestPath = join(dist, ".vite", "manifest.json");
if (!existsSync(viteManifestPath)) {
  fail("dist/.vite/manifest.json absent: run vite build first");
}
const viteManifest = JSON.parse(readFileSync(viteManifestPath, "utf8"));
rmSync(join(dist, ".vite"), { recursive: true });
const login = new Set(["index.html", "theme.js", "favicon.svg"]);
const visit = (key) => {
  const chunk = viteManifest[key];
  if (chunk === undefined) {
    fail(`Vite manifest without ${key}`);
  }
  if (login.has(chunk.file)) {
    return;
  }
  login.add(chunk.file);
  for (const file of [...(chunk.css ?? []), ...(chunk.assets ?? [])]) {
    login.add(file);
  }
  for (const imported of chunk.imports ?? []) {
    visit(imported);
  }
};
visit("index.html");

// 2. No absolute URL in what the browser interprets.
for (const path of walk(dist)) {
  if (!["html", "js", "css", "svg", "json"].includes(extension(path))) {
    continue;
  }
  const text = readFileSync(join(dist, path), "utf8");
  for (const match of text.matchAll(/(?:https?:|wss?:)?\/\/[A-Za-z0-9.-]+\.[A-Za-z]{2,}[^\s"'`)<>]*/g)) {
    const url = match[0];
    if (!/^(https?|wss?):/.test(url)) {
      // A protocol-relative URL is refused as well, unless it is a comment
      // line in the source map style, which the build never emits.
      fail(`${path}: protocol-relative URL ${url}`);
    }
    const clean = url.replace(/[.,;]+$/, "");
    if (!ALLOWED_URLS.some((allowed) => allowed.test(clean))) {
      fail(`${path}: absolute URL outside the allowed list: ${clean}`);
    }
  }
}

// 3. Licences of the shipped packages (dependencies, not devDependencies).
const lock = JSON.parse(readFileSync(join(root, "package-lock.json"), "utf8"));
const notices = [];
for (const [key, entry] of Object.entries(lock.packages).sort(([a], [b]) =>
  a < b ? -1 : a > b ? 1 : 0,
)) {
  if (key === "" || entry.dev === true) {
    continue;
  }
  const dir = join(root, key);
  const files = existsSync(dir)
    ? readdirSync(dir)
        .filter((n) => /^(licen[cs]e|copying|notice)/i.test(n))
        .sort()
    : [];
  if (!existsSync(join(dir, "package.json"))) {
    fail(`${key}: not installed, run npm ci first`);
  }
  const name = key.replace(/^.*node_modules\//, "");
  notices.push(`${"=".repeat(72)}\n${name} ${entry.version} (${entry.license})\n${"=".repeat(72)}\n`);
  if (files.length === 0) {
    // A few packages ship no licence file: their declared licence and
    // author stand for it.
    const meta = JSON.parse(readFileSync(join(dir, "package.json"), "utf8"));
    const author = typeof meta.author === "string" ? meta.author : meta.author?.name;
    notices.push(
      `No licence file in the package. Licence declared in package.json: ${entry.license}` +
        (author ? `, author: ${author}` : "") +
        ".\n\n",
    );
  }
  for (const file of files) {
    notices.push(readFileSync(join(dir, file), "utf8").replace(/\r\n/g, "\n").trimEnd() + "\n\n");
  }
}
writeFileSync(
  join(dist, "licenses.txt"),
  "Licences des composants tiers livrés dans le portail d'Ostena.\n\n" + notices.join(""),
);

// 4. Brotli variants, 5. SHA256SUMS and manifest.json.
const files = [];
for (const path of walk(dist)) {
  const ext = extension(path);
  const type = TYPES[ext];
  if (type === undefined) {
    fail(`${path}: extension .${ext} is not a served type`);
  }
  const raw = readFileSync(join(dist, path));
  let brotli = null;
  if (!COMPRESSED.has(ext)) {
    const compressed = brotliCompressSync(raw, {
      params: {
        [constants.BROTLI_PARAM_QUALITY]: 11,
        [constants.BROTLI_PARAM_SIZE_HINT]: raw.length,
        [constants.BROTLI_PARAM_MODE]:
          ext === "wasm" ? constants.BROTLI_MODE_GENERIC : constants.BROTLI_MODE_TEXT,
      },
    });
    if (compressed.length < raw.length) {
      writeFileSync(join(dist, `${path}.br`), compressed);
      brotli = { size: compressed.length, sha256: sha256(compressed) };
    }
  }
  files.push({ path, type, size: raw.length, sha256: sha256(raw), brotli });
}

const sums = files
  .flatMap((f) => [
    [f.path, f.sha256],
    ...(f.brotli ? [[`${f.path}.br`, f.brotli.sha256]] : []),
  ])
  .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
  .map(([path, digest]) => `${digest}  ${path}\n`)
  .join("");
writeFileSync(join(dist, "SHA256SUMS"), sums);

const sent = (f) => (f.brotli ? f.brotli.size : f.size);
const budget = {
  total: files.filter((f) => !f.path.endsWith(".wasm")).reduce((n, f) => n + sent(f), 0),
  login: files.filter((f) => login.has(f.path)).reduce((n, f) => n + sent(f), 0),
  wasm: files.filter((f) => f.path.endsWith(".wasm")).reduce((n, f) => n + sent(f), 0),
};
const manifest = {
  version: 1,
  digest: sha256(sums),
  budget,
  login: [...login].sort(),
  files,
};
writeFileSync(join(dist, "manifest.json"), JSON.stringify(manifest, null, 2) + "\n");
console.log(
  `pack: ${files.length} files, digest ${manifest.digest}\n` +
    `pack: brotli sizes: total ${budget.total} B (without .wasm), login page ${budget.login} B, ` +
    `WebAssembly ${budget.wasm} B`,
);
