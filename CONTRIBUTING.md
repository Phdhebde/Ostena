# Contribuer à Ostena

## Developer Certificate of Origin (DCO)

Chaque commit doit être signé selon le [DCO 1.1](https://developercertificate.org/). En signant, vous certifiez avoir le droit de soumettre ce code sous la licence du projet :

```bash
git commit -s
```

La ligne `Signed-off-by: Prénom Nom <email>` doit correspondre à l'auteur du commit. La CI le vérifie sur chaque pull request.

N'introduisez aucun code, document, test ou capture provenant d'un produit tiers ou d'un employeur. Le code s'écrit à partir des spécifications publiques (RFC, documentation Microsoft [MS-*]) et des bibliothèques open source autorisées.

## Commits et branches

- [Conventional Commits](https://www.conventionalcommits.org/), **en anglais** : `feat(grant): verify kid before signature`, `fix(ssh): …`, `ci: …`, `docs: …`, `chore: …`. La portée est le nom de la crate sans le préfixe `ostena-`.
- Petits commits, un seul sujet par commit.
- Jamais de push direct sur `main` : tout passe par une pull request avec une CI verte.

## Règles de code (résumé de CLAUDE.md)

- Rust édition 2024. `#![forbid(unsafe_code)]` dans toutes les crates, sauf `ostena-platform` et les intégrations matérielles ; chaque bloc `unsafe` y porte un commentaire `// SAFETY:` et un test.
- Les crates protocolaires (`ssh`, `rdp`, `tsgu`, `rfb`, `frame`) ne dépendent ni de la base ni de l'API.
- Toute la cryptographie passe par `ostena-crypto`. Pas de crypto maison, pas d'OpenSSL. Les algorithmes suivent les guides ANSSI et ne sont pas négociables.
- Les secrets vivent dans des types `Secret<…>` : jamais de `Debug`/`Display`, jamais de conversion en `String`, jamais journalisés.
- Lire un secret (`expose_secret`) est interdit par clippy ; chaque usage porte `#[expect(clippy::disallowed_methods)]` juste sous un commentaire `// SECRET-EXPOSURE: raison`, vérifié par `cargo xtask check-secrets`. Aucun secret dans le fichier de configuration : on y référence un chemin.
- Sécurité par défaut : toute option qui affaiblit la sécurité est journalisée et refusée en mode production.
- Pas de `unwrap()`/`expect()` hors tests et hors invariants documentés. Erreurs typées avec `thiserror` ; `anyhow` seulement dans les binaires et `xtask`.
- Dépendances : licences MIT, Apache-2.0, BSD-2/3-Clause, ISC, Zlib, MPL-2.0 uniquement (contrôlées par `cargo deny`). Seule exception : `Unicode-3.0` pour `unicode-ident`. Toute nouvelle dépendance se justifie dans la PR. Les dépendances git sont refusées par défaut ; une exception doit être épinglée par `rev`.
- Code, identifiants et commits en anglais ; documentation et ADR en français.

## Définition de « terminé »

1. CI verte : fmt, clippy `-D warnings`, tests Linux et Windows, `cargo deny check`.
2. Tests unitaires et de propriétés (`proptest`) ; une cible `cargo-fuzz` pour tout analyseur de données réseau.
3. Pas de régression de plus de 10 % sur les bancs de performance et d'empreinte.
4. Les événements d'audit correspondants sont émis et documentés.
5. Fonctionne hors ligne.
6. Documentation à jour ; un choix structurant donne lieu à un ADR dans `docs/adr/`.

## Commandes

```bash
cargo build --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all --check
cargo deny check
cargo xtask ci        # tout ce qui précède, dans l'ordre de la CI
cargo xtask check-secrets  # justification de chaque exposition de secret
cargo xtask vendor    # vendorise les dépendances dans vendor/
cargo xtask sbom      # SBOM CycloneDX dans target/sbom/
cargo xtask fuzz 60   # 60 s par cible de fuzz (Linux, cargo-fuzz)
cargo bench -p ostena-scope   # banc de la décision de périmètre (affiché, sans seuil)
cargo bench -p ostena-frame   # banc du décodage des trames (affiché, sans seuil)
cargo build -p ostena-frame --target wasm32-unknown-unknown   # cœur protocolaire du client web
```

Outils : `cargo install --locked cargo-deny cargo-cyclonedx cargo-fuzz`.

Fuzzing : le dossier `fuzz/` est hors du workspace et utilise le nightly épinglé dans `fuzz/rust-toolchain.toml`. libFuzzer ne fonctionne de façon fiable que sous Linux. Tout fichier gardé dans `fuzz/corpus/` est rejoué par `cargo test` sur la toolchain stable.

## Construction hors ligne

Sur une machine connectée :

```bash
cargo xtask vendor    # remplit vendor/ et écrit .cargo/vendor.toml
```

Transférez le dépôt avec `vendor/` et `.cargo/vendor.toml`, puis sur la machine isolée :

```bash
cargo build --offline --locked --config .cargo/vendor.toml
```

La toolchain épinglée doit aussi être transférée (archive `rustup` ou installateur autonome de la même version). Pour `cargo deny check advisories`, copiez la base d'avis RustSec et lancez `cargo deny check --disable-fetch`.
