# ADR-0002 : Chaîne de build reproductible et hors ligne

- **Statut** : Accepté
- **Date** : 2026-11-11

## Contexte

Le produit doit pouvoir être construit et exécuté en environnement isolé (air gap), sans aucun accès réseau. La chaîne d'approvisionnement doit être maîtrisée et traçable, pour l'évaluation CSPN comme pour les clients : licences contrôlées, dépendances inventoriées, binaires sans dépendance système imprévue.

## Décision

- **Toolchain épinglée** sur une version stable exacte dans `rust-toolchain.toml` (1.99.1 au lot L0), avec les cibles `x86_64-unknown-linux-musl`, `aarch64-unknown-linux-musl` et `x86_64-pc-windows-msvc`. Toute montée de version passe par une PR dédiée.
- **Binaires statiques** : musl pour Linux ; CRT statique (`+crt-static`) pour Windows MSVC, pour éviter le redistribuable Visual C++ sur les passerelles.
- **Vendorisation** : `cargo xtask vendor` copie toutes les dépendances dans `vendor/` et écrit `.cargo/vendor.toml`. La construction isolée se fait avec `cargo build --offline --locked --config .cargo/vendor.toml`. `Cargo.lock` est versionné.
- **`xtask` sans dépendance** (bibliothèque standard uniquement), pour qu'il compile avant toute vendorisation. Il orchestre des outils externes (`cargo vendor`, `cargo deny`, `cargo cyclonedx`) au lieu de les embarquer.
- **Politique de dépendances** contrôlée par `cargo-deny` : liste blanche de licences, registre crates.io uniquement, dépendances git refusées par défaut (une exception doit être épinglée par `rev`), doublons de versions refusés sauf exception justifiée, OpenSSL interdit.
- **SBOM CycloneDX** (JSON, spécification 1.5) générée par `cargo xtask sbom` et publiée par la CI.
- **CI GitHub Actions**, actions tierces épinglées par SHA de commit, permissions en lecture seule.

## Conséquences

- La construction hors ligne est possible dès qu'on dispose du dépôt vendorisé et de la toolchain épinglée ; transférer la toolchain reste une étape manuelle.
- `cargo-deny` (avis de sécurité) a besoin d'une copie locale de la base RustSec en environnement isolé (`--disable-fetch`).
- La cible `aarch64-unknown-linux-musl` est installée mais pas encore construite en CI : il faut un éditeur de liens croisé ou un runner ARM. À traiter avec le packaging.
- Les dépendances qui compilent du C (par exemple `aws-lc-rs`, attendu dans `ostena-crypto`) demanderont une chaîne C musl et CMake en CI et sur les postes de build. À traiter quand la dépendance arrivera.
- La reproductibilité bit à bit des binaires (chemins, horodatages) n'est pas encore vérifiée ; ce sera une tâche `xtask` ultérieure.

## Note (2026-11-11) : aws-lc-rs

Constat au lot L1, sans changement de la décision :

- `aws-lc-rs` (via `aws-lc-sys`) est compilé avec la crate `cc`, **sans CMake ni Go** en mode standard. Sous Windows, la fonctionnalité `prebuilt-nasm` fournit les objets assembleur précompilés livrés dans la crate : NASM est inutile et le build fonctionne hors ligne. Pour la cible musl, `musl-gcc` (paquet `musl-tools`) est nécessaire, en CI comme sur les postes de build.
- Le futur **mode FIPS** (`aws-lc-fips-sys`) exigera en plus **CMake et Go** sur les machines de build, y compris en environnement isolé. Il faudra les intégrer à la chaîne hors ligne, en versions épinglées, le moment venu.
