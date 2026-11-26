# ADR-0011 : Socle du core et base PostgreSQL

- **Statut** : Accepté, y compris l'exception de licence Unicode-3.0 de `stringprep`, acceptée le 2026-11-15 (section « Écarts »). Implémenté dans le lot M1, PR 2.
- **Date** : 2026-11-14
- **Amendé** : 2026-11-26 — rôles PostgreSQL séparés (propriétaire du schéma, rôle du service, audit en insertion seule), `ostena core db init`, migrations réversibles à partir de la 6 (jalon M2, PR 3). Voir « Rôles de la base ».

## Contexte

Jusqu'ici, seul le core de test (`ostena-tunnel`, fonctionnalité `testing`) jouait le rôle du core : registre des agents et jetons d'enrôlement en mémoire, perdus à chaque arrêt. Le jalon M1 demande un vrai core qui redémarre sans rien perdre, avec la base PostgreSQL 16 annoncée dans l'architecture, des requêtes vérifiées à la compilation et des migrations embarquées. La construction doit rester possible hors ligne, Windows compris.

## Décision

### Le core, composant Linux

- **Nouvelle crate `ostena-core`**, seule autorisée à dépendre de sqlx (`deny.toml`).
- **Commandes** : `ostena core run` (service), `ostena core db init` (rôles et base), `ostena core migrate [--check | --revert-to <version>]`, `ostena core agent token|list|revoke`.
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
- **Rôles séparés** (amendement du 2026-11-26) : voir « Rôles de la base ». En M1, un seul rôle possédait le schéma et l'appliquait lui-même au démarrage.

### Rôles de la base

En M1, le core se connectait avec un seul rôle, propriétaire du schéma : un core compromis pouvait modifier le schéma, par exemple désactiver les déclencheurs d'ajout seul de la chaîne d'audit. Depuis l'amendement du 2026-11-26 :

- **Deux rôles de groupe**, sans connexion (`NOLOGIN`), aux noms fixes puisque les migrations les nomment :
  - `ostena_owner` possède la base et tous les objets du schéma. Seul `ostena core migrate` le prend.
  - `ostena_app` reçoit des migrations, table par table, les seuls droits DML dont le service a besoin. Sur la chaîne d'audit (`audit_record`, `audit_head`), c'est `SELECT` et `INSERT` seulement : ni `UPDATE`, ni `DELETE`, ni `TRUNCATE`, ni `TRIGGER`, ni la propriété des tables. Le service ne peut donc plus désactiver les déclencheurs d'ajout seul. Aucune requête du core ne supprime de ligne : `ostena_app` n'a `DELETE` sur aucune table. Une table seulement verrouillée (`FOR SHARE`) reçoit `UPDATE` sur une seule colonne (`disabled_at`), ce que PostgreSQL exige pour un verrou de ligne.
- **Deux comptes système et deux rôles de connexion**, pour que `peer` reste la seule authentification (option la plus simple à auditer de la note M1, sans table `pg_ident`) :
  - `core.database.user` (`ostena` par défaut) : le service et les commandes d'administration ;
  - `core.database.migration_user` (`ostena_admin` par défaut, nouveau champ) : `ostena core migrate`, lancé par l'exploitant lors d'une mise à jour.
  Chacun est membre de son rôle de groupe avec `SET TRUE` et `INHERIT FALSE` : sans `SET ROLE`, il ne peut rien faire d'autre que se connecter. Chaque connexion du core commence par `SET ROLE` (`ostena_app` ou `ostena_owner`), et le core vérifie `current_user` avant de servir le pool. Un rôle de connexion qui reprend le nom d'un rôle de groupe est refusé (`CFG-V013`).
- **`ostena core db init`**, lancé sous le superutilisateur PostgreSQL (`sudo -u postgres`), crée ce qui manque : les deux rôles de groupe, les deux rôles de connexion et leurs appartenances, la base propriété d'`ostena_owner`, dont seuls les deux rôles de connexion peuvent ouvrir une session (`REVOKE ALL … FROM PUBLIC`, `GRANT CONNECT`). Sur une installation M1, il donne en plus à `ostena_owner` la base et les objets que possédait le compte du service (`REASSIGN OWNED`). Il est idempotent et signale ce qui affaiblit la séparation. Il ne lit aucun fichier du service (clés, transcripts) : leurs règles (`CFG-P011`, `CFG-P016`) ne s'appliquent ni à lui ni à `ostena core migrate`, lancés sous d'autres comptes.
- **Le core ne migre plus** : `ostena core run` exige un schéma à jour (`CORE-E005`), puis vérifie, avant tout, qu'aucun objet du schéma n'appartient à son rôle de connexion ni à `ostena_app` (installation M1 non convertie) et qu'`ostena_app` n'a aucun droit de modification sur la chaîne d'audit (`CORE-E013`, dans les deux modes).
- **Affaiblissements refusés en production** : un rôle de connexion du service superutilisateur, membre d'`ostena_owner`, capable de créer des rôles, ou qui sert aussi aux migrations, est journalisé (`core.database_role_weak`) et refusé en production (`CORE-E014`) par `ostena core run` et par chaque commande d'administration ; `ostena core db init` refuse d'emblée un même compte pour le service et les migrations, et sort en erreur s'il laisse un affaiblissement. En développement, ils sont tolérés et journalisés. La démonstration et la CI tournent en production sous deux comptes système distincts ; les tests d'intégration, qui n'ont qu'un compte de test, tournent en développement et vérifient le refus en production.
- **Droits des tables futures** : toute migration qui ajoute une table accorde dans la même migration ce dont `ostena_app` a besoin. Le test des droits (`crates/ostena-core/tests/roles.rs`) liste chaque droit d'`ostena_app` et échoue sur tout autre, comme sur une table oubliée.

### Schéma et requêtes

- **Migrations embarquées** (`sqlx::migrate!`), appliquées par `ostena core migrate` sous le verrou consultatif de sqlx, en tant qu'`ostena_owner` (en M1 : par `ostena core run` au démarrage).
  - Une base migrée par un binaire plus récent, une migration modifiée ou une migration en échec sont refusées (`CORE-E005`).
  - `ostena core run` et les commandes d'administration exigent un schéma à jour et ne le modifient jamais.
  - **Migrations réversibles à partir de la 6** : chacune a un fichier `.down.sql` (format réversible de sqlx, `MIGRATOR.undo`), qui ramène le schéma à la version précédente sans toucher aux lignes que celle-ci connaît. `ostena core migrate --revert-to <version>` les applique avant la réinstallation d'un binaire plus ancien ; une version antérieure à 5 est refusée (`CORE-E004`), les migrations M1 n'ayant pas d'inverse. Le test `crates/ostena-core/tests/migrations.rs`, lancé en CI, fait pour chaque migration réversible N : N-1 → N → N-1 → N sur une base qui contient des lignes, et compare le schéma (colonnes, contraintes, index, déclencheurs, fonctions, propriétaires, droits) et toutes les lignes.
  - Les fichiers `.sql` simples des migrations 1 à 5 ne changent pas : leur somme de contrôle reste celle qu'une base M1 a enregistrée.
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

- **Trois clés** : celle du certificat serveur (`tls_private_key`), celle de la CA émettrice (`issuing_private_key`) et celle qui signe les têtes de la chaîne d'audit (`[core.audit] signing_key`, ADR-0012). S'y ajoutent la clé des grants (`grant_signing_key`) et les deux autorités SSH (`[core.ssh] user_ca_key`, `host_ca_key`) de l'ADR-0014. Les règles ci-dessous valent pour toutes, et deux clés du core ne partagent jamais la même source (`CFG-V016`).
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
| `CORE-E010` | écriture d'audit impossible (chaîne ou export) : l'opération auditée est refusée, sauf si elle ne fait que retirer des droits (ADR-0012) |
| `CORE-E011` | chaîne d'audit incohérente : le core cesse de signer et refuse de démarrer (ADR-0012) |
| `CORE-E012` | requête d'administration invalide (ADR-0014) |
| `CORE-E013` | rôles de la base absents ou mal attribués : rôle de groupe inaccessible au rôle de connexion, migration hors d'`ostena_owner`, objet du schéma possédé par le compte du service, ou droit de modification d'`ostena_app` sur la chaîne d'audit |
| `CORE-E014` | séparation des rôles de la base affaiblie, refusée en production : rôle de connexion du service superutilisateur, membre d'`ostena_owner`, capable de créer des rôles, ou identique au rôle des migrations |

Les refus d'accès (`ACC-E001` à `ACC-E009`) et d'inventaire (`INV-E001` à `INV-E005`) sont décrits dans l'ADR-0014.

Côté tunnel, `TUN-E029` signale un registre illisible (ADR-0008).

### Événements

Les événements qui engagent une décision du core sont écrits dans la chaîne d'audit, avec leur classe d'échec d'écriture (accordant, protecteur, au mieux) : voir l'[ADR-0012](0012-chaine-d-audit-du-core.md). Le journal structuré reçoit aussi :
- **démarrage** : `core.started`, `core.stopped`, `core.database_connected` (méthode d'authentification, rôle de la session), `core.database_not_peer` (développement), `core.database_role_weak` (séparation des rôles affaiblie ; refusée en production, `CORE-E014`), `config.waiver` ;
- **schéma** : `core.migrated` et `core.migration_reverted`, écrits aussi dans la chaîne d'audit par `ostena core migrate` (acteur : le compte de migration), `core.database_initialized` (`ostena core db init`, une ligne par changement) ;
- **registre** : `core.registry_unavailable`, `core.registry_restored`, `core.registry_error`, `core.notices_interrupted` ;
- **agents** : `tunnel.agent_connected`, `tunnel.refused`, `agent.certificate_renewed`, `agent.renewal_refused`, `agent.revoked`, `agent.revocation_applied` (tunnels fermés) ;
- **enrôlement** (ADR-0008) : `enroll.token_issued`, `enroll.listener_opened`, `enroll.listener_closed`, `enroll.accepted`, `enroll.refused`, `enroll.store_unavailable` ;
- **chaîne d'audit** (ADR-0012) : `audit.chain_started`, `audit.head_signed` (tête sous forme texte), `audit.chain_broken`, `audit.break_accepted`, `audit.break_acknowledged`, `audit.append_failed`, `audit.event_dropped`, `audit.events_lost`, `audit.head_failed` ;
- **accès SSH et inventaire** (ADR-0014) : `grant.key_activated`, `access.ssh_granted`, `access.ssh_refused`, `access.session_opened`, `access.session_refused`, `access.session_closed`, `ssh.host_certified`, `ssh.host_key_refused`, `login_session.revoked`, `login_session.revocation_applied`, et les changements d'inventaire.

### Écarts

1. **Cryptographie de `sqlx-postgres`** : l'authentification SCRAM et MD5 tire `sha2`, `hmac`, `hkdf`, `md-5` et `rand` (RustCrypto), sans condition. Aucun pilote PostgreSQL en Rust pur n'y échappe (`tokio-postgres` fait pareil). Exception acceptée, limitée à `sqlx-postgres` comme parent autorisé dans `deny.toml` et consignée dans l'ADR-0009. Avec `peer`, ce code n'est jamais exécuté.
2. **Licence Unicode-3.0 : exception acceptée le 2026-11-15.** `stringprep` (SASLprep du SCRAM, dépendance inconditionnelle de `sqlx-postgres`) tire `unicode-normalization` et `unicode-properties`, sous `(MIT OR Apache-2.0) AND Unicode-3.0`, liées au binaire du core. Sans elles, il n'y a pas de sqlx sans fork. L'exception est limitée à ces deux crates et à ce seul chemin : `deny.toml` les admet sous Unicode-3.0 et interdit qu'elles soient tirées par autre chose que `stringprep`, lui-même tiré par `sqlx-postgres` seulement. CLAUDE.md la mentionne. Toute autre crate sous Unicode-3.0 reste refusée.
   - Les tables ICU tirées par `url` (via `idna`) sont évitées : `idna_adapter` est épinglé à sa version 1.0.0, qui n'accepte que l'ASCII, et les crates `icu_*` sont bannies.
3. **Doublons de versions** : sqlx 0.9 mêle deux générations de dépendances (`sha2` 0.10 et 0.11, `base64` 0.22, `hashbrown` 0.16). Ils sont déclarés dans `deny.toml`, et liés au seul binaire Linux.

## Conséquences

- **Le vrai core existe** : l'agent s'enrôle auprès de lui, survit à ses redémarrages et en est coupé dès sa révocation. Un test de démonstration lance le vrai binaire des deux côtés (Linux, base réelle).
- **Installation** : PostgreSQL 16 sur la machine du core, deux comptes système (`ostena`, `ostena_admin`), `ostena core db init` sous `postgres`, et `local … peer` dans `pg_hba.conf` pour ces deux rôles ([installation du core](../exploitation/core-installation.md), avec la procédure de passage d'une installation M1).
- **Mise à jour** : `ostena core migrate` sous le compte d'administration, puis redémarrage du service ; le service refuse de démarrer tant que le schéma n'est pas à jour.
- **Tests** : ceux qui demandent une base sont obligatoires en CI (`OSTENA_REQUIRE_DB=1`, socket et `peer`) et sautés en local avec un message sans serveur. Chaque test crée sa propre base, propriété d'`ostena_owner` ; le rôle de test, qui doit pouvoir créer des rôles, joue les deux rôles de connexion, et les tests du core passent par `ostena_app` comme le service : un droit manquant à une migration fait échouer les tests existants.
- **Dépendances** : le binaire Linux lie 58 crates de plus (sqlx et ses dépendances, dont une partie, comme `futures` ou `hmac`, était déjà dans l'espace de travail sans être liée au binaire). Le binaire Windows ne change pas. `sqlx-core` active aussi la macro `#[instrument]` de `tracing` (compilation seulement, `syn` 2 déjà présent). Le fichier `Cargo.lock` liste en plus les pilotes MySQL et SQLite de sqlx, jamais compilés. La revue complète figure dans la description de la PR.
- **Le core de test reste** pour les tests d'`ostena-tunnel`. Le module `ostena_core::testing` (fonctionnalité `testing`) porte la même marque que lui, et `cargo xtask check-release` refuse l'un comme l'autre.
