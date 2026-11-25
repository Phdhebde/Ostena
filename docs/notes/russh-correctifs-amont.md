# Note : correctifs amont possibles pour russh, ssh-key et sqlx

- **Statut** : liste tenue à jour ; décision après le jalon M1 de les proposer ou non.
- **Date** : 2026-11-14
- **Origine** : réduction des dépendances de russh 0.65.1 (M1, PR 1), [ADR-0009](../adr/0009-choix-cryptographiques.md) (écart SSH), [ADR-0010](../adr/0010-acces-ssh-natif.md), puis de sqlx 0.9 (M1, PR 2), [ADR-0011](../adr/0011-socle-du-core-et-postgresql.md).

Avec la liste figée, beaucoup de ce que russh compile ne sert pas. Rien ne peut être retiré de notre côté : russh active lui-même les fonctionnalités de `ssh-key`, et ses dépendances sont inconditionnelles. Ce qui suit serait à proposer en amont, sous forme de fonctionnalités Cargo, actives par défaut pour ne rien casser chez les autres utilisateurs.

| Proposition | Effet pour nous | Crates évitées |
|---|---|---|
| `pageant` optionnel (fonctionnalité, par défaut active) | **prioritaire** : supprime l'import d'`oleaut32`, donc `combase` et `msvcp_win` dans le service Windows | `pageant`, 10 crates `windows-*`, une partie de `futures` |
| P-384 et P-521 optionnels | moins de code lié | `p384`, `p521` |
| Ed25519 / X25519 optionnels | moins de code lié, plus d'algorithme hors liste compilé | `ed25519`, `ed25519-dalek`, `curve25519-dalek(-derive)` |
| échange post-quantique X25519 + ML-KEM optionnel | idem | `ml-kem`, `module-lattice`, `kem`, `sha3`, `shake`, `keccak` |
| ne plus activer `macros` de tokio dans `russh-util` | évite `tokio-macros` et un `syn` 2 | `tokio-macros` |
| chiffrement des clés privées de `ssh-key` non forcé | moins de code de dérivation | `argon2`, `bcrypt-pbkdf`, `blowfish`, `scrypt`, `pbkdf2` |
| ECDH et ECDSA par le moteur `aws-lc-rs` déjà présent | **lèverait l'écart cryptographique** de l'ADR-0009 | une partie de RustCrypto |

En attendant, le chargement différé d'`oleaut32` à la liaison (ADR-0009) neutralise l'effet de `pageant` sur le service Windows, sans fork.

## Défaut de `ssh-key 0.7.0-rc.11`

Clé P-256 refusée quand OpenSSH encode son scalaire sur 31 octets (ADR-0010). Signalement à déposer par le responsable du projet ; texte prêt dans la description de la PR 1 du jalon M1.

## sqlx 0.9 (ADR-0011)

| Proposition | Effet pour nous |
|---|---|
| **TLS : la CA configurée remplace les racines publiques au lieu de s'y ajouter** (`tls_rustls.rs`, `import_root_certs()` puis `add`) | **prioritaire** pour une base distante : permettrait une TLS épinglée vers PostgreSQL, sans `webpki-roots` (CDLA-Permissive-2.0) |
| moyen d'effacer `password` et `options` venus de l'environnement (`PGPASSWORD`, `PGOPTIONS`), ou un constructeur qui ne lit pas l'environnement | lèverait le refus `CORE-E008` |
| `stringprep` (SASLprep) optionnel, lié à SCRAM | retirerait `unicode-normalization` et `unicode-properties` (Unicode-3.0) d'un binaire qui n'utilise que `peer` |
| authentifications SCRAM et MD5 optionnelles | retirerait `md-5`, `hmac`, `hkdf` et une génération de `sha2` du binaire |
| `sqlx-core` sur `sha2` 0.11 et `base64` 0.23, comme `sqlx-postgres` | supprimerait les doublons de versions déclarés dans `deny.toml` |
| ne plus activer les fonctionnalités par défaut de `tracing` | évite `tracing-attributes` |
