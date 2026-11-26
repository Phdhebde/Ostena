# CLAUDE.md

> À placer à la racine du dépôt. Claude Code le lit automatiquement à chaque session.
> Nom : **Ostena**. Dépôt public : github.com/Phdhebde/Ostena, licence AGPL-3.0-or-later.

## Le projet

Ostena est un bastion d'administration (PAM) open source, on premise, pour environnements très sensibles. Il donne des accès SSH, RDP et VNC **natifs** (le client habituel de l'administrateur, sans plugin) et via un **portail web** (HTML5), avec une traçabilité forte et des droits granulaires et limités dans le temps. Il est conçu comme s'il devait passer une **CSPN ANSSI**.

Exigences qui priment sur tout le reste :

- Latence ajoutée < 20 ms (objectif p99 : ≤ 3 ms SSH, ≤ 5 ms RDP passthrough, ≤ 10 ms navigateur).
- Établissement d'une session < 5 s.
- Empreinte minimale en CPU et mémoire : chaque dépendance et chaque allocation doivent se justifier.
- Le bastion s'adapte à l'existant du client (AD, LDAPS, SSO OIDC/SAML, RDS, Intune/Entra ID), pas l'inverse.
- Fonctionne entièrement hors ligne (air gap) : aucune dépendance réseau au build ni à l'exécution.

## Architecture en bref

- **ostena-core** (Linux) : identités multi-sources, inventaire, politiques d'accès, workflows, API (axum REST + OpenAPI, tonic gRPC interne en mTLS), base **PostgreSQL 16+** propre au produit (sqlx, requêtes vérifiées à la compilation, migrations embarquées).
- **Agent passerelle** (Windows Server 2016+ et Debian 12+) : **un agent par groupe de cibles**, en passerelle de rebond. Il ouvre les sessions vers les cibles et joue l'authentification (Kerberos, CredSSP, clés SSH). Aucun agent sur les cibles. Aucune base de données sur l'agent. Il se connecte au core par un tunnel *dial-back* mTLS multiplexé (QUIC, repli TLS 1.3 sur TCP avec un multiplexeur maison ; ADR-0008).
- **Grant de session** : le core autorise et signe un jeton court (ECDSA P-256 / SHA-256, `kid`, TTL 60 s, usage unique, anti-rejeu persistant). Le jeton porte l'autorisation, **jamais le secret**.
- **Audit** : chaîne HMAC, horodatage RFC 3161, stockage WORM, export syslog/OCSF, outil `ostena-verify`.
- **Coffre-fort** : module séparé, installable plus tard sur une autre machine, cryptographie hybride post-quantique (échange de clés et enveloppe des secrets : P-256 + ML-KEM-768 ; signatures : ECDSA P-256 + ML-DSA-65 ; voir l'ADR-0009). Il ne vit jamais sur le bastion.
- Un **binaire unique** `ostena` dont les rôles sont activés à l'installation.

## Organisation du dépôt (cible)

Monorepo, *workspace* Cargo. Ne créer une crate que lorsqu'un lot en a besoin.

```text
crates/
  ostena-common/      configuration TOML stricte, erreurs, journaux structurés, métriques, types Secret
  ostena-crypto/      SEULE crate autorisée à appeler la cryptographie (rustls / aws-lc-rs)
  ostena-grant/       grants ECDSA P-256, jeu de clés par kid, anti-rejeu persistant
  ostena-frame/       framing binaire versionné gateway <-> navigateur
  ostena-scope/       CIDR autorisés/interdits, épinglage de l'IP résolue, anti-SSRF
  ostena-session/     gestionnaire de sessions, quotas, trait Driver
  ostena-tunnel/      tunnel dial-back mTLS multiplexé, priorité aux entrées clavier/souris
  ostena-ssh/         russh, serveur natif + driver client, transcripts
  ostena-rdp/         IronRDP + sspi-rs, serveur natif + driver client, passthrough EGFX
  ostena-tsgu/        RD Gateway (MS-TSGU)
  ostena-rfb/         VNC (RFB 3.3–3.8, VeNCrypt)
  ostena-webproxy/    proxy des applications web
  ostena-recorder/    enregistrements (MKV H.264, asciicast v2)
  ostena-audit/       chaîne scellée, export SIEM, ostena-verify
  ostena-policy/      modèle d'autorisation compilé, fenêtres horaires, PDP
  ostena-core/        identités, inventaire, workflows, API, PostgreSQL
  ostena-vault/       coffre-fort (module séparé)
  ostena-platform/    service NT / systemd, IPC local
  ostena-web-client/  cœur protocolaire en WebAssembly
  ostena-cli/         point d'entrée du binaire et sous-commandes (clap)
portal/               SPA Svelte + TypeScript, embarquée dans le binaire
packaging/  lab/  tests/  docs/  xtask/
```

## Règles de code (non négociables)

- Rust édition 2024. `#![forbid(unsafe_code)]` partout, sauf `ostena-platform` et les intégrations matérielles (PKCS#11, TPM) : chaque bloc `unsafe` a un commentaire `// SAFETY:` et un test.
- Les crates protocolaires (`ssh`, `rdp`, `tsgu`, `rfb`, `frame`) ne dépendent ni de la base ni de l'API : testables et *fuzzables* seules.
- Toute la cryptographie passe par `ostena-crypto`. Pas de crypto maison, pas d'OpenSSL. Algorithmes figés selon les guides ANSSI (PG-083, PA-035), pas négociables par un client ou un jeton.
  Seule exception : TOTP HMAC-SHA-1 par défaut, écart accepté (ADR-0009).
- Secrets dans des types `Secret<…>` (`secrecy` + `zeroize`) : jamais `Debug`/`Display`, jamais convertis en `String`, jamais journalisés.
- Sécurité par défaut : le comportement par défaut est le plus sûr. Toute option qui l'affaiblit est journalisée et **refusée en mode production** (validation au démarrage). Exemples de refus : vérification de clé hôte SSH non stricte, certificat RDP de la cible non épinglé sans PKI, repli NTLM quand un mot de passe est délégué, grant signé avec un autre algorithme qu'ECDSA P-256 / SHA-256.
- Contrôle de périmètre (CIDR + épinglage de l'IP résolue + blocage des adresses de métadonnées cloud et locales) appliqué à **tous** les drivers.
- Pas de `unwrap()`/`expect()` hors tests et hors invariants documentés. Erreurs typées (`thiserror`), `anyhow` seulement dans les binaires et `xtask`.
- Dépendances : licences MIT, Apache 2.0, BSD, ISC, Zlib, MPL 2.0 uniquement, contrôlées par `cargo-deny`. Préférer peu de dépendances, bien maintenues. Toute nouvelle dépendance se justifie dans la PR.
  Seule exception : `Unicode-3.0`, admise uniquement pour les crates suivantes, déclarées dans `deny.toml` :
  - `unicode-ident` (tables Unicode, dépendance de compilation des macros procédurales, non liée au binaire) ;
  - `unicode-normalization` et `unicode-properties`, liées au binaire du core, et seulement par le chemin `sqlx-postgres` → `stringprep` (ADR-0011). Les crates `icu_*` et toute autre crate sous Unicode-3.0 restent refusées.
- Exclu en production : JVM, Node, Python, Redis, Kafka, Elasticsearch, Kubernetes obligatoire, FreeRDP/guacd.

## Définition de « terminé »

1. CI verte : `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`, tests Linux et Windows, `cargo deny check`.
2. Tests unitaires et de propriétés (`proptest`) ; pour tout analyseur de données réseau, une cible `cargo-fuzz`.
3. Pas de régression de plus de 10 % sur les bancs de performance. Pour l'empreinte, une régression bloque si elle dépasse à la fois +10 % et 1 Mio en valeur absolue.
4. Les événements d'audit correspondants sont émis et documentés.
5. Fonctionne hors ligne.
6. Documentation à jour ; un choix structurant = un ADR court dans `docs/adr/` (format : contexte, décision, conséquences).

## Commandes

```bash
cargo build --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all --check
cargo deny check
cargo xtask <tâche>        # build reproductible, SBOM, etc.
# Requêtes du core : après une migration ou une requête modifiée, régénérer le
# cache hors ligne contre une base de développement migrée.
(cd crates/ostena-core && DATABASE_URL=postgres://… cargo sqlx prepare -- --all-targets)
# Tests qui demandent PostgreSQL (sautés sinon) : OSTENA_TEST_DB_SOCKET ou
# OSTENA_TEST_DB_TCP, avec OSTENA_TEST_DB_USER (voir ostena_core::testing).
# Ce rôle doit avoir CREATEDB et CREATEROLE (il crée les rôles du core,
# ADR-0011) ; seul compte de test, il joue le service et les migrations :
# les tests du binaire tournent en mode development et vérifient le refus
# en production (CORE-E014).
```

(À compléter au fil de l'eau quand des commandes s'ajoutent.)

## Façon de travailler attendue de Claude

- Langue : code, identifiants et messages de commit en anglais ; documentation, ADR et échanges en français.
- Avant un changement non trivial : proposer un plan court, puis attendre validation.
- Écrire les tests en même temps que le code, et les faire tourner avant de déclarer une tâche finie.
- Petits commits, un sujet par commit, signés (`git commit -s`, DCO). PR vers `dev` ; ne jamais pousser sur `main` directement.
- Signaler toute exigence ci-dessus qui semble impossible à tenir plutôt que de la contourner en silence.

## Confidentialité et propriété intellectuelle

- Le dépôt est **public** (licence AGPL-3.0-or-later, fichier `LICENSE`). Tout ce qui est poussé, y compris les messages de commit, les branches et les descriptions de PR, est visible de tous. Ne publier aucun paquet, image ou version sans décision explicite du mainteneur.
- Le code est écrit à partir des spécifications publiques (RFC, documentation Microsoft [MS-RDPBCGR], [MS-RDPEGFX], [MS-TSGU], etc.) et des bibliothèques open source citées. N'y introduire aucun code, document, test ou capture provenant d'un produit tiers ou d'un employeur, et ne pas les mentionner dans le code, les commentaires, les ADR ou les messages de commit.
- Chaque crate déclare `license.workspace = true`. Les dépendances restent soumises à la liste de licences permissives de `deny.toml` : aucune dépendance sous copyleft fort (GPL, AGPL).
