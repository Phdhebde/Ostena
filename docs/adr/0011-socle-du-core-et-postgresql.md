# ADR-0011 : Socle du core et base PostgreSQL

- **Statut** : Accepté, sauf l'exception de licence Unicode-3.0 de `stringprep`, en attente de décision (section « Écarts »). Implémenté dans le lot M1, PR 2.
- **Date** : 2026-11-14

## Contexte

Jusqu'ici, seul le core de test (`ostena-tunnel`, fonctionnalité `testing`) jouait le rôle du core : registre des agents et jetons d'enrôlement en mémoire, perdus à chaque arrêt. Le jalon M1 demande un vrai core qui redémarre sans rien perdre, avec la base PostgreSQL 16 annoncée dans l'architecture, des requêtes vérifiées à la compilation et des migrations embarquées. La construction doit rester possible hors ligne, Windows compris.

## Décision

### Le core, composant Linux

- **Nouvelle crate `ostena-core`**, seule autorisée à dépendre de sqlx (`deny.toml`).
- **Commandes** : `ostena core run` (service), `ostena core migrate [--check]`, `ostena core agent token|list|revoke`.
- **`ostena-cli` ne lie `ostena-core` que pour les cibles Linux.** Le binaire Windows, qui ne fait tourner que l'agent, n'embarque ni le core ni PostgreSQL. Ce n'est pas une liaison conditionnelle par plateforme pour des raisons d'empreinte : le core est Linux par conception (voir l'architecture dans CLAUDE.md). Le cas d'`ostena-ssh` est différent : l'agent Windows aura besoin du serveur SSH, et sa liaison n'est pas conditionnelle (ADR-0009).
- La crate compile aussi sous Windows, pour clippy et les tests hors base.

### Connexion à PostgreSQL

- **sqlx `=0.9.0`**, avec les seules fonctionnalités `postgres`, `runtime-tokio`, `macros`, `migrate` et `tls-none`.
- **En production, un seul chemin : le socket Unix local avec l'authentification `peer`**. Il n'y a ni mot de passe, ni réseau, ni TLS à configurer.
  - Au démarrage, le core lit `system_user`, qui vaut `peer:<compte>` en `peer` et `null` en `trust`. Toute autre méthode est refusée en production (`CORE-E003`). Si le serveur demande SCRAM ou MD5, la connexion échoue faute de mot de passe, puisqu'aucun n'est configurable en production.
  - TCP (`core.database.tcp`) est refusé en production (`CFG-P014`) et accepté en développement seulement, avec un mot de passe lu dans un fichier.
  - PostgreSQL 16 au moins (`CORE-E002`).
- **Pourquoi pas TLS** : quand on lui donne une CA, sqlx l'**ajoute** au magasin des racines publiques (`webpki-roots`) au lieu de la mettre seule. N'importe quelle autorité publique pourrait alors présenter le serveur. En plus, `webpki-roots` est sous licence CDLA-Permissive-2.0. Une base distante avec une TLS épinglée viendra après M1, avec un correctif amont (racines remplacées, pas ajoutées ; voir la [note des correctifs](../notes/russh-correctifs-amont.md)).
- **Environnement** : chaque champ de connexion vient de la configuration. sqlx lit les variables `PG*` et aucun réglage ne peut ensuite effacer `PGPASSWORD` ni `PGOPTIONS` (options passées au serveur, par exemple `-c search_path=…`) : le core refuse de démarrer si l'une des deux est définie (`CORE-E008`). Les autres variables (`PGHOST`, `PGUSER`, `PGSSLMODE`…) sont sans effet, ce que vérifie un test lancé dans un sous-processus. `~/.pgpass` n'est jamais lu.
- **Un seul rôle**, propriétaire du schéma. Séparer un rôle DDL d'un rôle DML est préférable, mais avec `peer` il faut alors deux comptes système ou une table `pg_ident`. C'est noté pour après M1 ([note](../notes/core-roles-base.md)).

### Schéma et requêtes

- **Migrations embarquées** (`sqlx::migrate!`), appliquées par `ostena core run` sous le verrou consultatif de sqlx.
  - Une base migrée par un binaire plus récent, une migration modifiée ou une migration en échec sont refusées (`CORE-E005`).
  - Les commandes d'administration exigent un schéma à jour et ne le modifient jamais.
- **Requêtes vérifiées à la compilation** (`query!`) contre le cache `crates/ostena-core/.sqlx`, versionné. `SQLX_OFFLINE=true` est fixé dans `.cargo/config.toml` : la compilation ne joint jamais de base. `cargo sqlx prepare` (outil de développement, absent du build isolé) régénère le cache, et la CI vérifie qu'il est à jour.
- **Tables** : `agent` (identifiant, groupe, révocation), `agent_certificate` (empreinte SHA-256, agent, révocation), `enrollment_token` (identifiant, **condensat SHA-256 du secret de 256 bits, jamais le secret**, groupe, échéance, usage, échecs, brûlage).

### Registre des agents

- **Jetons en base**, puisque `ostena core agent token` tourne dans un autre processus que le core.
  - **Consommation atomique** : la ligne est verrouillée (`SELECT … FOR UPDATE`) le temps des contrôles, puis écrite telle que les contrôles l'ont laissée, qu'ils aient réussi ou non (jeton consommé, compteur d'échecs, brûlage au troisième). Deux tentatives simultanées sont donc tranchées l'une après l'autre (test avec 8 tentatives concurrentes).
  - **Comparaison du secret en temps constant**, sur son condensat.
  - L'émission notifie le core (`NOTIFY`), qui ouvre son écouteur d'enrôlement. Au démarrage, le core l'ouvre aussi s'il reste un jeton valide.
- **Écriture d'abord en base** : un certificat n'est remis à l'agent qu'une fois son empreinte enregistrée. Un échec refuse l'enrôlement (`TUN-E029`) au lieu de distribuer un certificat inconnu du core. Le renouvellement ajoute une empreinte, et l'ancienne reste valide jusqu'à son expiration ou sa révocation.
- **Copie du registre pour la poignée de main TLS** : rustls interroge le registre de façon synchrone. Le core garde donc une copie, chargée au démarrage, mise à jour après chaque écriture et rechargée en entier toutes les 60 s.
  - **Si la copie ne peut pas être rechargée, elle devient indisponible** : tout nouvel agent est refusé (`TUN-E029`, événement `core.registry_unavailable`) jusqu'au prochain rechargement réussi, retenté toutes les 5 s. Le core ne sert jamais une copie périmée. Les tunnels déjà ouverts restent ouverts.
- **Révocation** : `ostena core agent revoke` révoque l'agent et tous ses certificats, puis notifie le core, qui ferme aussitôt ses tunnels (`TUN-E005`). Chaque rechargement ferme aussi les tunnels que la copie n'accepte plus, au cas où une notification aurait été perdue (reconnexion de l'écoute).

### Clés du core

- **Lecture** depuis un credential systemd (`LoadCredentialEncrypted=`, lu dans `$CREDENTIALS_DIRECTORY`) ou depuis un fichier PKCS#8.
- **Fichier en clair** (`CFG-P012`) : **dérogation datée**, accepté en production et journalisé à chaque démarrage (`config.waiver`) **jusqu'au 2027-04-30 inclus**, refusé ensuite.
- **Droits** : une clé en fichier lisible au-delà du compte du service est refusée (`CFG-P011`).
- **Contrôle de cohérence** : la clé de la CA émettrice doit être celle de son certificat, dont le nom est lu dans le certificat lui-même.
- `CFG-P013` (credential lié au TPM 2.0) est réservé, et sera contrôlé après M1.

### Codes

| Code | Erreur |
|---|---|
| `CORE-E001` | base injoignable ou requête en échec |
| `CORE-E002` | PostgreSQL antérieur à 16 |
| `CORE-E003` | authentification autre que `peer` en production |
| `CORE-E004` | migration en échec |
| `CORE-E005` | schéma différent de celui du binaire (plus récent, modifié, en échec, ou non migré pour une commande d'administration) |
| `CORE-E006` | clé ou certificat du core inutilisable |
| `CORE-E007` | démarrage impossible (écouteur, paramètre hors bornes) |
| `CORE-E008` | `PGPASSWORD` ou `PGOPTIONS` dans l'environnement |
| `CORE-E009` | agent inconnu |

Côté tunnel, `TUN-E029` signale un registre illisible (ADR-0008).

### Événements

Journal structuré, en attendant la chaîne d'audit (PR 3) :
- **démarrage** : `core.started`, `core.stopped`, `core.database_connected` (méthode d'authentification), `core.database_not_peer` (développement), `core.migrated`, `config.waiver` ;
- **registre** : `core.registry_unavailable`, `core.registry_error`, `core.notices_interrupted` ;
- **agents** : `tunnel.agent_connected`, `tunnel.refused`, `agent.certificate_renewed`, `agent.renewal_refused`, `agent.revoked`, `agent.revocation_applied` (tunnels fermés) ;
- **enrôlement** (ADR-0008) : `enroll.token_issued`, `enroll.listener_opened`, `enroll.listener_closed`, `enroll.accepted`, `enroll.refused`, `enroll.store_unavailable`.

### Écarts

1. **Cryptographie de `sqlx-postgres`** : l'authentification SCRAM et MD5 tire `sha2`, `hmac`, `hkdf`, `md-5` et `rand` (RustCrypto), sans condition. Aucun pilote PostgreSQL en Rust pur n'y échappe (`tokio-postgres` fait pareil). Exception acceptée, limitée à `sqlx-postgres` comme parent autorisé dans `deny.toml` et consignée dans l'ADR-0009. Avec `peer`, ce code n'est jamais exécuté.
2. **Licence Unicode-3.0 : décision attendue.** `stringprep` (SASLprep du SCRAM, dépendance inconditionnelle de `sqlx-postgres`) tire `unicode-normalization` et `unicode-properties`, sous `(MIT OR Apache-2.0) AND Unicode-3.0`, et elles seraient liées au binaire du core. CLAUDE.md n'admet Unicode-3.0 que pour `unicode-ident`. Une exception limitée à ces deux crates figure dans `deny.toml`, marquée comme en attente. Sans elle, il n'y a pas de sqlx sans fork.
   - Les tables ICU tirées par `url` (via `idna`) sont évitées : `idna_adapter` est épinglé à sa version 1.0.0, qui n'accepte que l'ASCII, et les crates `icu_*` sont bannies.
3. **Doublons de versions** : sqlx 0.9 mêle deux générations de dépendances (`sha2` 0.10 et 0.11, `base64` 0.22, `hashbrown` 0.16). Ils sont déclarés dans `deny.toml`, et liés au seul binaire Linux.

## Conséquences

- **Le vrai core existe** : l'agent s'enrôle auprès de lui, survit à ses redémarrages et en est coupé dès sa révocation. Un test de démonstration lance le vrai binaire des deux côtés (Linux, base réelle).
- **Installation** : PostgreSQL 16 sur la machine du core, un rôle portant le nom du compte du service, et `local … peer` dans `pg_hba.conf` ([installation du core](../exploitation/core-installation.md)).
- **Tests** : ceux qui demandent une base sont obligatoires en CI (`OSTENA_REQUIRE_DB=1`, socket et `peer`) et sautés en local avec un message sans serveur. Chaque test crée sa propre base.
- **Dépendances** : le binaire Linux lie 58 crates de plus (sqlx et ses dépendances, dont une partie, comme `futures` ou `hmac`, était déjà dans l'espace de travail sans être liée au binaire). Le binaire Windows ne change pas. `sqlx-core` active aussi la macro `#[instrument]` de `tracing` (compilation seulement, `syn` 2 déjà présent). Le fichier `Cargo.lock` liste en plus les pilotes MySQL et SQLite de sqlx, jamais compilés. La revue complète figure dans la description de la PR.
- **Le core de test reste** pour les tests d'`ostena-tunnel`. Le module `ostena_core::testing` (fonctionnalité `testing`) porte la même marque que lui, et `cargo xtask check-release` refuse l'un comme l'autre.
