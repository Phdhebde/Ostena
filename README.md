# Ostena

> Nom de travail, non définitif.

Ostena est un bastion d'administration (PAM) open source, déployé sur site, pour les environnements très sensibles. Il donne des accès SSH, RDP et VNC natifs (avec le client habituel de l'administrateur) et via un portail web HTML5, avec une traçabilité forte et des droits granulaires, limités dans le temps. Il est conçu dans la perspective d'une CSPN ANSSI.

**État : lot L0 (fondations).** Le dépôt compile, se teste et se vérifie en CI ; aucune fonctionnalité produit n'est encore disponible.

## Construire

Prérequis : `rustup`. La version de Rust est épinglée dans `rust-toolchain.toml`.

```bash
cargo build --workspace
cargo test --workspace
cargo xtask ci          # fmt, clippy, tests, cargo-deny, comme la CI
```

Construction hors ligne : voir [CONTRIBUTING.md](CONTRIBUTING.md#construction-hors-ligne).

## Documentation

- [CONTRIBUTING.md](CONTRIBUTING.md) : règles de contribution
- [SECURITY.md](SECURITY.md) : signaler une vulnérabilité
- [docs/adr/](docs/adr/README.md) : décisions d'architecture

## Licence

Pas encore décidée. Le dépôt est privé.
