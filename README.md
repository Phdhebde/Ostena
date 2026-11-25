<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/assets/ostena-logo-sombre.svg">
    <img src="docs/assets/ostena-logo-clair.svg" alt="Ostena" width="320">
  </picture>
</p>

<p align="center">
  <a href="https://github.com/Phdhebde/Ostena/actions/workflows/ci.yml?query=branch%3Adev"><img src="https://github.com/Phdhebde/Ostena/actions/workflows/ci.yml/badge.svg?branch=dev" alt="CI"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/licence-AGPL--3.0--or--later-8C1D40" alt="Licence AGPL-3.0-or-later"></a>
  <a href="rust-toolchain.toml"><img src="https://img.shields.io/badge/rust-1.99.1-1A1214" alt="Rust 1.99.1"></a>
</p>

Ostena est un bastion d'administration (PAM) open source, déployé sur site, pour les environnements très sensibles. Il donne des accès SSH, RDP et VNC **natifs**, avec le client habituel de l'administrateur et sans greffon, ainsi qu'un portail web HTML5. Chaque accès est tracé, et les droits sont granulaires et limités dans le temps. Il est conçu comme s'il devait passer une certification CSPN de l'ANSSI.

> **État : en développement, pas encore utilisable en production.** Aucune version n'est publiée. Le premier jalon (M1) porte sur l'accès SSH natif par certificats.

## Principes

- **Natif et rapide** : latence ajoutée visée sous 3 ms (p99) en SSH, ouverture de session en moins de 5 s.
- **Sobre** : un binaire unique en Rust, peu de dépendances, une empreinte mémoire mesurée à chaque changement.
- **Sûr par défaut** : toute option qui affaiblit la sécurité est journalisée et refusée en mode production. Algorithmes cryptographiques figés selon les guides de l'ANSSI.
- **Traçable** : chaîne d'audit scellée et signée, vérifiable hors du bastion.
- **Adapté à l'existant** : AD, LDAPS, SSO OIDC et SAML, RDS, Entra ID. Fonctionne entièrement hors ligne.

## Architecture

- **Core** (Linux) : identités, inventaire, politiques d'accès, audit, base PostgreSQL propre au produit.
- **Agent passerelle** (Windows Server 2016+ et Debian 12+) : un agent par groupe de cibles, en passerelle de rebond. Il ouvre les sessions vers les cibles et joue l'authentification ; rien n'est installé sur les cibles. Il rejoint le core par un tunnel mTLS sortant.
- **Coffre-fort** : module séparé, installable plus tard sur une autre machine, avec une cryptographie hybride post-quantique.

Les choix structurants sont décrits dans les [ADR](docs/adr/README.md).

## Construire

Prérequis : `rustup` (la version de Rust est épinglée dans `rust-toolchain.toml`) et `cargo install --locked cargo-deny cargo-cyclonedx`.

```bash
cargo build --workspace
cargo test --workspace
cargo xtask ci          # fmt, clippy, tests, cargo-deny, comme la CI
```

Construction hors ligne : voir [CONTRIBUTING.md](CONTRIBUTING.md#construction-hors-ligne). Installation et exploitation du core : [docs/exploitation/](docs/exploitation/).

## Contribuer

Les contributions sont bienvenues : lisez [CONTRIBUTING.md](CONTRIBUTING.md) (commits signés selon le DCO, règles de code) et le [code de conduite](CODE_OF_CONDUCT.md). Le développement se fait sur la branche `dev`.

**Une vulnérabilité ne se signale jamais dans un ticket public** : voir [SECURITY.md](SECURITY.md).

## Licence

Ostena est distribué sous la licence [GNU Affero General Public License v3.0 ou ultérieure](LICENSE) (AGPL-3.0-or-later). Toute version modifiée mise à disposition par le réseau doit en offrir le code source à ses utilisateurs : un bastion en service reste ainsi auditable par ceux qui s'en servent.
