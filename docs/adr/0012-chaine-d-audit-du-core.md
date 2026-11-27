# ADR-0012 : Chaîne d'audit du core

- **Statut** : Accepté. Implémenté dans le lot M1 : format et vérificateur (PR 3a), intégration au core (PR 3b).
- **Révisé** : 2026-11-26 — rôles séparés de la base (ADR-0011) : insertion seule pour le service ; `core.migration_reverted`.
- **Date** : 2026-11-15
- **Révision** : 2026-11-25, événements des transcripts et codes `AUD-E017` à `AUD-E020`, `AUD-W005` à `AUD-W008` ; `transcript.refused` de classe protectrice (jalon M1, PR 8, ADR-0016)
- **Révision** : 2026-11-27, suite du lot L6 (jalon M2, PR 11) : stockage en ajout seul des fichiers scellés (champ `immutable` de `transcript.sealed`, `REC-E006`, `CFG-P024`)
- **Révision** : 2026-11-27, horodatage RFC 3161 des têtes (jalon M2, PR 11b) : `audit.head_timestamped`, `audit.timestamp_failed`, `AUD-E021`, `AUD-W009`, `TSP-E001` à `TSP-E007`
- **Révision** : 2026-11-27, export syslog TLS en OCSF (jalon M2, PR 11c) : `audit.forwarded`, `audit.forward_failed`, `SYS-E001`, `SYS-E002`, `AUD-E022`, `CFG-V021`
- **Révision** : 2026-11-27, file chiffrée des bilans de session de l'agent (jalon M2, PR 11d) : `agent.reports_lost` (accordant), messages `report_ack` et `reports_lost` du tunnel (ADR-0008)
- **Révision** : 2026-11-26, événements du portail et classes (`web_session.*`, `user.role_granted`, `user.role_revoked`), champ `channel` des connexions (jalon M2, PR 8a, ADR-0020)
- **Révision** : 2026-11-27, demande d'accès du portail : `access.web_granted` (accordant), `access.web_refused` (au mieux) (jalon M2, PR 8b, ADR-0020)
- **Révision** : 2026-11-27, passerelle du portail : `gateway.opened` (accordant), `gateway.refused` et `gateway.closed` (au mieux) (jalon M2, PR 8b, ADR-0020)

## Contexte

Le core prend des décisions qu'un auditeur doit pouvoir reconstituer et dont il doit pouvoir prouver l'intégrité : enrôlement et révocation des agents, renouvellement des certificats, tunnels refusés, options affaiblissantes, démarrages et migrations. Jusqu'ici, ces événements ne vont qu'au journal structuré (ADR-0011), qui ne protège ni contre la suppression ni contre la modification.

Contraintes :

- un auditeur vérifie un export **hors ligne**, sur son poste, **sans aucun secret** et sans accès au core ;
- l'administrateur qui exploite le core ne doit pas pouvoir effacer ou réécrire une trace sans que cela se voie ;
- le format est lu par un code exposé à des données hostiles (un export peut être fabriqué) : décodeur **strict, canonique, fuzzable**, sans dépendance ;
- mémoire constante : une chaîne peut compter des millions d'enregistrements ;
- algorithmes figés selon les guides ANSSI (ADR-0009) ; place réservée à l'horodatage RFC 3161 et aux signatures hybrides post-quantiques.

CLAUDE.md annonçait une « chaîne HMAC ». Cet ADR retient une chaîne de hash publique signée par ECDSA (voir plus bas) ; CLAUDE.md sera aligné séparément.

## Décision

### Crate

Nouvelle crate `ostena-audit`, indépendante de la plateforme et sans base de données. Dépendances : `ostena-crypto` et `thiserror`, aucune crate tierce nouvelle. Elle fournit le format des enregistrements, un constructeur d'événements, les têtes signées, le conteneur d'export, le vérificateur en flux et des points d'entrée de fuzzing. Le core l'utilise pour écrire en base, signer les têtes et exporter, avec le même vérificateur pour contrôler ses propres segments (section « Intégration au core »).

### Enregistrement v1

Encodage binaire canonique, entiers big-endian :

| Taille | Champ | Règle |
|---|---|---|
| 1 | version | 1, sinon `AUD-E002` |
| 16 | identifiant de chaîne | tiré au hasard au démarrage de la chaîne |
| 8 | seq | à partir de 1, sans trou |
| 32 | hash précédent | hash de l'enregistrement `seq − 1` ; nul si et seulement si `seq = 1` |
| 8 | heure (ms Unix) | horloge du core |
| 1 | résultat | 0 succès, 1 refus, 2 échec |
| 1 | type d'acteur | 0 core, 1 administrateur, 2 agent, 3 pair, 4 utilisateur (ADR-0014) |
| 1 + n | acteur | UTF-8, au plus 128 octets, sans caractère de contrôle |
| 1 + n | événement | ASCII `[a-z0-9_.]`, de 3 à 64 octets |
| 1 | nombre de champs | au plus 32 |
| … | champs | longueur du nom (`u8`), nom `[a-z0-9_]` de 1 à 32 octets, **strictement croissants** octet par octet ; type (`u8`) ; longueur (`u16`) ; valeur |

Types de valeur : 1 texte (UTF-8, au plus 1024 octets, sans caractère de contrôle), 2 entier `u64` (8 octets), 3 octets (au plus 256), 4 UUID (16 octets), 5 booléen (1 octet, 0 ou 1). Aucun octet en trop, au plus 8192 octets au total.

- **Hash d'un enregistrement** : `SHA-256("ostena-audit-record-v1" ‖ 0x00 ‖ corps)`.
- **Décodeur strict** : tout ce qui n'est pas l'unique encodage canonique est refusé (`AUD-E001`), si bien que `encode(decode(b)) == b` pour tout `b` accepté. Un même événement n'a qu'une représentation, donc qu'un hash. L'absence de caractère de contrôle dans l'acteur et les textes évite aussi l'injection de séquences d'échappement dans le terminal de l'auditeur.
- **Événements** : le type `EventKind` liste les événements écrits par le core : `audit.chain_started`, `audit.signing_started`, `audit.events_lost`, `audit.break_acknowledged`, `audit.exported`, `core.started`, `core.stopped`, `core.migrated`, `core.migration_reverted` (ces deux-là écrits par `ostena core migrate`, acteur le compte de migration), `core.database_not_peer`, `config.waiver`, `core.registry_unavailable`, `core.registry_restored`, `enroll.token_issued`, `enroll.token_consumed`, `enroll.token_rejected`, `agent.enrolled`, `agent.certificate_renewed`, `agent.revoked`, `agent.revocation_applied`, `agent.renewal_refused`, `tunnel.agent_connected`, `tunnel.refused`, et ceux de l'accès SSH et de l'inventaire (ADR-0014) : `grant.key_activated`, `access.ssh_granted`, `access.ssh_refused`, `access.session_opened`, `access.session_refused`, `access.session_closed`, `agent.reports_lost` (ADR-0012, PR 11d), `ssh.host_certified`, `ssh.host_key_refused`, `login_session.revoked`, `login_session.revocation_applied`, `user.created`, `user.disabled`, `resource.created`, `target_account.created`, `right.granted`, `right.revoked`, `gateway_group.updated`, et ceux d'`ostena login` (ADR-0010) : `login.succeeded`, `login.refused`, `login.locked`, `user.password_set`, `user.totp_enrolled`, `user.totp_reset`, `user.unlocked`, et ceux des transcripts (ADR-0016) : `access.ssh_exec`, `transcript.sealed`, `transcript.refused`, et ceux des transferts et redirections SSH (ADR-0010) : `access.ssh_transfer`, `access.ssh_forward`, `access.ssh_request_refused`, et ceux du portail (ADR-0020) : `web_session.expired`, `web_session.source_changed`, `web_session.reauthenticated`, `user.role_granted`, `user.role_revoked`, `access.web_granted`, `access.web_refused`, `gateway.opened`, `gateway.refused`, `gateway.closed`, et ceux des sources d'identités (ADR-0021) : `identity.sync_completed`, `identity.source_unavailable`, `identity.source_restored`, `identity.user_provisioned`, `identity.user_reenabled`, `user_group.created`, `user_group.member_added`, `user_group.member_removed`, et ceux du point de décision des accès (ADR-0022) : `policy.installed`, `policy.invalidated`, `access_rule.created`, `access_rule.revoked`, `account_group.created`, `account_group.member_added`, `account_group.member_removed`, `admin.role_cumulation_used`. Le décodeur accepte tout nom bien formé, pour qu'un vérificateur ancien lise une chaîne plus récente.
- **Noms de champs** (`ostena_audit::field`) : aucun ne contient un fragment que la rédaction des journaux masque (`key`, `token`, `secret`…), pour que les mêmes noms servent dans le journal structuré : `kid` pour un identifiant de clé, `p256_public` pour une clé publique, `enrollment_id` pour un jeton d'enrôlement (jamais le jeton lui-même). Un test le vérifie.

### Chaînage SHA-256 et têtes ECDSA plutôt qu'un HMAC

Chaque enregistrement porte le hash du précédent ; le core signe périodiquement le bout de la chaîne avec ECDSA P-256 (une *tête*).

Alternative écartée : une chaîne HMAC, où chaque maillon est authentifié par une clé secrète.

- **Vérification publique** : avec une signature, l'auditeur et les commandes d'administration vérifient avec la seule clé publique. Avec un HMAC, il faudrait leur confier la clé, qui permet aussi de forger des maillons, ou centraliser la vérification sur le core.
- **Un HMAC n'apporte rien contre un core compromis** : celui qui contrôle le core détient la clé HMAC comme la clé de signature, et peut réécrire la fin de la chaîne dans les deux cas. Ce qui protège alors, ce sont les têtes déjà sorties du core (copie externe, export antérieur), et une signature se vérifie là où elles sont conservées.
- **Fenêtre résiduelle** : entre deux têtes, un administrateur qui écrit directement en base (sans passer par le core) peut modifier les derniers enregistrements non encore signés et recalculer leurs hash. Cette fenêtre est bornée par la cadence des têtes, et l'export la signale (`AUD-W001`, enregistrements non couverts).
- Un HMAC pourra être **ajouté plus tard** comme colonne supplémentaire, sans changer le format des enregistrements ni des têtes, si une exigence le demande.

### Tête v1

182 octets fixes, big-endian. Partie signée (118 octets) :

| Offset | Taille | Champ | Règle |
|---|---|---|---|
| 0 | 1 | version | 1, sinon `AUD-E002` |
| 1 | 16 | identifiant de chaîne | |
| 17 | 8 | numéro de tête | à partir de 1, sans trou |
| 25 | 8 | seq couvert | dernier enregistrement couvert, au moins 1 |
| 33 | 32 | hash de cet enregistrement | |
| 65 | 32 | hash de la tête précédente | nul si et seulement si numéro = 1 |
| 97 | 8 | heure (ms Unix) | |
| 105 | 4 | battement (s) | au moins 1 : une tête est produite au moins aussi souvent |
| 109 | 1 | algorithme | 2 (ECDSA P-256 / SHA-256), comme les grants ; sinon `AUD-E002` |
| 110 | 8 | kid | 8 premiers octets du SHA-256 de la clé publique SEC1 non compressée, même définition que les grants (ADR-0004) |

Puis la signature `r ‖ s` de 64 octets, forme low-S, vérifiée strictement par `ostena-crypto` (ADR-0004), sur `"ostena-audit-head-v1" ‖ 0x00 ‖ partie signée`. Le **hash de tête**, repris par la tête suivante, est `SHA-256("ostena-audit-head-hash-v1" ‖ 0x00 ‖ partie signée ‖ signature)`.

- **Forme texte** : `ostena-audit-head-v1:` suivi de 364 chiffres hexadécimaux minuscules, décodage strict. Elle se recopie dans un ticket, un courriel ou un second système, et sert de tête externe.
- **Clés de confiance** : au plus 16, indexées par kid (la clé courante et les précédentes de la chaîne).

### Export v1

Conteneur lu et écrit en flux :

- en-tête de 40 octets : magic `OSTAUD\0\x01`, identifiant de chaîne, heure de l'export (ms Unix), premier seq ;
- trames : type (`u8`), longueur (`u32`, au plus 8192), contenu. Type 1 : corps d'enregistrement tel que stocké ; 2 : tête ; 3 : réservé à un jeton RFC 3161, refusé en v1 ; `0xFF` : fin, avec le nombre d'enregistrements et de têtes ;
- ordre : l'enregistrement k, puis les têtes dont le seq couvert vaut k ;
- **export partiel** (premier seq au-dessus de 1) : la première trame est la tête d'ancrage N, avec `seq couvert + 1 = premier seq` ;
- rien après la trame de fin ; une trame de fin absente, un compte faux, une trame trop longue ou d'un type inconnu sont des erreurs (`AUD-E004`).

### Vérificateur

Le vérificateur reçoit, dans l'ordre de la chaîne, l'ancre éventuelle, les enregistrements et les têtes. Il ne garde que le bout courant, la dernière tête et des compteurs : mémoire constante. Il vérifie :

- le format de chaque élément, l'identifiant de chaîne, la suite des seq et le chaînage des hash ;
- la signature de chaque tête, sa correspondance avec le bout de la chaîne à sa position, la suite des numéros de tête et des hash de tête ;
- les têtes externes : chacune doit être valide, et l'export doit contenir son seq couvert avec le même hash. Seq absent : troncature ; hash différent : divergence (`AUD-E013`). Une tête externe antérieure au début d'un export partiel (hors ancre) n'est pas comparable et est ignorée ;
- la fraîcheur : écart entre têtes et âge de la dernière tête au moment de l'export.

Il continue après une erreur (un enregistrement illisible est supposé occuper la place attendue) et garde au plus 1000 constats, les autres étant comptés. Options : têtes externes, tolérance d'horloge (5 s par défaut), tolérance de retard d'une tête au-delà de son battement (60 s par défaut).

Commande : `ostena audit verify <export> --key <fichier de clé publique>... [--head <texte ou fichier>]... [--json]`, sur toutes les plateformes. Les clés sont les fichiers `ostena-p256-public-key-v1` écrits par `ostena ca key new`. Codes de sortie :

| Code | Signification |
|---|---|
| 0 | chaîne intacte, entièrement couverte par une tête signée |
| 1 | au moins une erreur |
| 2 | avertissements seulement |
| 3 | erreur d'utilisation ou d'entrée/sortie (y compris les erreurs de syntaxe de la ligne de commande) |

### Codes

Codes stables, jamais renumérotés ni réutilisés. Chaque message commence par son code, entre crochets.

| Code | Gravité | Signification |
|---|---|---|
| `AUD-E001` | erreur | enregistrement mal formé |
| `AUD-E002` | erreur | version ou algorithme non pris en charge |
| `AUD-E003` | erreur | tête mal formée |
| `AUD-E004` | erreur | export mal formé, tronqué ou illisible |
| `AUD-E005` | erreur | identifiant de chaîne différent |
| `AUD-E006` | erreur | seq inattendu (suppression, réordonnancement, doublon) |
| `AUD-E007` | erreur | chaînage des hash rompu |
| `AUD-E008` | erreur | signature de tête invalide |
| `AUD-E009` | erreur | kid inconnu |
| `AUD-E010` | — | réservé |
| `AUD-E011` | erreur | tête incohérente avec le bout de la chaîne |
| `AUD-E012` | erreur | suite des têtes rompue (numéro ou hash de la tête précédente) |
| `AUD-E013` | erreur | troncature ou divergence par rapport à une tête externe |
| `AUD-E014` | erreur | export partiel sans ancre de confiance |
| `AUD-E015` | erreur | échec cryptographique (signature d'une tête, tirage d'un identifiant de chaîne) |
| `AUD-E016` | erreur | plus de 16 clés de confiance |
| `AUD-W001` | avertissement | fin de chaîne non couverte par une tête (avec le nombre d'enregistrements) |
| `AUD-W002` | avertissement | horloge qui recule au-delà de la tolérance |
| `AUD-W003` | avertissement | écart entre deux têtes supérieur au battement plus la tolérance |
| `AUD-W004` | avertissement | dernière tête plus ancienne que deux battements au moment de l'export |
| `AUD-E017` | erreur | transcript scellé absent du répertoire (`--transcripts`, ADR-0016) |
| `AUD-E018` | erreur | transcript modifié depuis son scellement (taille ou SHA-256) |
| `AUD-W005` | avertissement | fichier de transcript sans scellé dans l'export |
| `AUD-W006` | avertissement | transcript scellé incomplet (avec son code `REC-E…`) |
| `AUD-E019` | erreur | session SSH ouverte dans l'export (`access.session_opened`) sans `transcript.sealed`, alors qu'elle aurait dû finir (`--transcripts`) |
| `AUD-E020` | erreur | `transcript.sealed` aux champs absents ou mal formés, ou second sceau pour la même session |
| `AUD-W007` | avertissement | session SSH sans transcript scellé, peut-être encore ouverte à l'instant de l'export (`--transcripts`) |
| `AUD-W008` | avertissement | sceau de transcript postérieur à la dernière tête signée (`--transcripts`) |
| `AUD-E021` | erreur | horodatage d'une tête invalide : champs mal formés, hash différent de celui de la tête, tête pas encore lue, ou jeton refusé par les ancres de l'autorité (`--tsa-ca`, avec son code `TSP-E…`) |
| `AUD-W009` | avertissement | heure d'un horodatage antérieure à celle de la tête qu'il couvre, au-delà de la tolérance et de la précision du jeton |

### Place réservée

- **Horodatage RFC 3161** : réalisé par la PR 11b (voir la suite), dans des enregistrements de la chaîne et non dans une trame d'export. La trame de type 3 reste réservée et refusée.
- **Têtes hybrides v2** : ECDSA P-256 + ML-DSA-65 par concaténation, comme prévu par l'ADR-0009 pour les têtes de chaîne d'audit, dans une tête de version 2 avec son propre algorithme. Les enregistrements ne changent pas. Bloquant : ML-DSA n'est exposé par `aws-lc-rs` que derrière une fonctionnalité instable (ADR-0009).

### Intégration au core

#### Schéma (migration `0002_audit_chain`)

- `audit_record` : `seq` (clé, au moins 1), `body` (le corps encodé, de 73 à 8192 octets : `MIN_RECORD_LEN` et `MAX_RECORD_LEN`), `hash` (32 octets), `event` (nom, pour l'index `(event, seq)`), `recorded_at`.
- `audit_head` : `head_no` (clé, au moins 1), `record_seq` (référence `audit_record`), `body` (182 octets), `hash` (32 octets), `signed_at` ; index sur `record_seq`.
- **Ajout seul** : déclencheurs `BEFORE UPDATE OR DELETE` (par ligne) et `BEFORE TRUNCATE` sur les deux tables, qui lèvent `insufficient_privilege` ; `REVOKE UPDATE, DELETE, TRUNCATE … FROM PUBLIC`.
- **Contiguïté** : un déclencheur `BEFORE INSERT` impose `seq = max + 1`, `head_no = max + 1` et une tête qui ne dépasse pas le dernier enregistrement.
- **Rôles séparés** (ADR-0011, amendement du 2026-11-26) : le rôle du service, `ostena_app`, n'a que `SELECT` et `INSERT` sur ces tables, sans en être propriétaire : il ne peut ni modifier, ni supprimer, ni vider, ni désactiver un déclencheur, et le core refuse de démarrer si un tel droit lui est accordé (`CORE-E013`). Seul le propriétaire du schéma, `ostena_owner`, pris par `ostena core migrate`, le peut encore, comme tout administrateur de la base. **L'intégrité reste cryptographique** (chaînage, têtes signées, contrôle du core et `ostena audit verify`) : en M1, avec un rôle unique propriétaire, ces protections n'arrêtaient que les erreurs.

#### Écriture

- Chaque ajout prend le verrou consultatif de transaction `AUDIT_LOCK_KEY` (au-dessus de 2^62, il ne peut pas croiser celui des migrations de sqlx), lit le bout de la chaîne, le contrôle contre son contenu et insère l'enregistrement suivant. Le verrou est tenu jusqu'à la fin de la transaction : les seq suivent l'ordre des validations, sans trou.
- L'ajout est **la dernière instruction avant le `COMMIT`**, dans une transaction `READ COMMITTED`.
- **Seul `ostena core run` démarre une chaîne** : identifiant tiré au hasard, `audit.chain_started` au seq 1, sous le même verrou, donc une seule fois même si plusieurs processus démarrent ensemble, et journalisé au niveau avertissement pour qu'une nouvelle chaîne inattendue se voie. Il refuse (`CORE-E011`) s'il trouve des têtes sans aucun enregistrement. Un ajout sur une chaîne vide échoue (`CORE-E010`, « chaîne d'audit non initialisée : démarrez le core ») : une opération accordante est alors refusée, une opération protectrice validée quand même. Ainsi, une commande d'administration ne remplace jamais en silence des tables vidées par une chaîne neuve.
- L'acteur d'une commande d'administration est l'utilisateur de la base (`system_user`, `peer:<compte>` en production).

#### Classes d'échec d'écriture

| Classe | Événements | Si l'enregistrement ne peut pas être écrit |
|---|---|---|
| **Accordant** | `agent.enrolled`, `agent.certificate_renewed` (choisi d'après l'insertion de la ligne `agent`), `enroll.token_issued`, `enroll.token_consumed`, `audit.signing_started`, `core.migrated`, `core.migration_reverted` (écrits par `ostena core migrate` après le changement du schéma, qui reste fait si l'écriture échoue : la commande sort alors en erreur avec `CORE-E010`), `config.waiver`, `core.started`, `audit.break_acknowledged`, `audit.exported`, `grant.key_activated`, `access.ssh_granted`, `access.web_granted` (dans la transaction qui enregistre le grant), `gateway.opened` (dans la transaction qui marque le grant présenté), `access.session_opened`, `ssh.host_certified`, `gateway_group.updated`, `user.created`, `resource.created`, `target_account.created`, `right.granted`, `login.succeeded`, `web_session.reauthenticated` (dans la transaction qui remplace l'empreinte du cookie), `user.role_granted`, `user.password_set`, `user.totp_enrolled`, `user.unlocked`, `transcript.sealed` (avec l'état scellé de la ligne `session_transcript` ; un échec la laisse `recording`, et elle est scellée incomplète au démarrage suivant), `agent.reports_lost` (écrit avant l'accusé de réception rendu à l'agent : sans écriture, l'agent renvoie l'avis) | écrit dans la transaction du changement ; l'échec l'annule et le refuse (`TUN-E029` côté tunnel, `CORE-E010` sinon) ; le core refuse de démarrer |
| **Protecteur** | `agent.revoked`, `enroll.token_rejected` (échecs, brûlage, code), `login_session.revoked`, `user.disabled`, `right.revoked`, `login.locked`, `user.totp_reset`, `login.refused` pour un compte connu (dans la transaction qui compte l'échec ou relit le compte), `user.role_revoked`, `user_group.member_removed`, `web_session.expired` et `web_session.source_changed` (dans la transaction qui révoque la session), `transcript.refused` (dans sa propre transaction, après l'arrêt du flux) | écrit dans un point de sauvegarde ; le changement est validé quand même ; l'échec est journalisé (`audit.append_failed`, niveau erreur) et compté |
| **Au mieux** | `tunnel.agent_connected`, `tunnel.refused` (agent identifié), `agent.renewal_refused`, `agent.revocation_applied`, `core.registry_unavailable`, `core.registry_restored`, `core.stopped`, `access.ssh_refused`, `access.web_refused`, `gateway.refused`, `gateway.closed`, `access.session_refused`, `access.session_closed`, `ssh.host_key_refused`, `login_session.revocation_applied`, `login.refused` pour un nom inconnu (aucune ligne à verrouiller), `access.ssh_exec`, `access.ssh_transfer`, `access.ssh_forward`, `access.ssh_request_refused` | file bornée de 256 événements, écrite par une seule tâche par lots (un verrou par lot), avec reprise ; les événements perdus sont comptés, puis consignés par `audit.events_lost` (nombre, premier et dernier instant) dès que la chaîne est de nouveau inscriptible. `core.stopped` est écrit de façon synchrone, en 2 s au plus |

Restent au seul journal : les refus d'un pair non authentifié (jeton inconnu, poignée de main refusée) et les événements des écouteurs.

#### Têtes

- **Clé** : `[core.audit] signing_key`, une clé P-256 générée sur le core par `ostena ca key new` et transmise comme les autres clés du core (credential systemd chiffré, fichier toléré jusqu'au 2027-04-30). Sa clé publique est distribuée aux auditeurs. Elle est annoncée dans la chaîne par `audit.signing_started` (kid, clé publique de 65 octets, battement) : après un changement de clé, le core ancre son contrôle sur la dernière tête signée par l'ancienne clé, dont il retrouve la clé publique dans cet enregistrement.
- **Contrôle avant signature** : sous le même verrou, le core repasse le segment depuis la tête précédente (l'ancre) dans le vérificateur, vérifie que l'enregistrement couvert par l'ancre est toujours là avec le même hash, que la colonne `hash` correspond au corps, et que les enregistrements qu'il a lui-même écrits depuis l'ancre (au plus `head_max_records`) ont gardé leur seq et leur hash. Il signe alors la tête suivante, l'insère et journalise `audit.head_signed` avec la tête sous forme texte, son numéro et le seq couvert.
- **Rupture** : si le contrôle échoue, le core journalise `audit.chain_broken`, cesse de signer et `ostena core run` refuse de démarrer (`CORE-E011`). Un administrateur qui a constaté et documenté la rupture l'acquitte (`ostena core audit acknowledge-break --seq N`, enregistrement `audit.break_acknowledged`) : le contrôle suivant accepte les ruptures situées avant cet enregistrement et à partir de N, puis la signature reprend. La rupture reste visible pour tout vérificateur.
- **Cadence** : une tête après chaque enregistrement accordant ou protecteur écrit par le core et à chaque notification sur le canal du registre (les commandes d'administration notifient avec leur enregistrement) ; toutes les `head_interval_secs` (60 s par défaut) si le bout a bougé ; dès que `head_max_records` (1000) enregistrements ne sont pas couverts ; toutes les `heartbeat_secs` (300 s) même sans changement ; au démarrage, après le contrôle, et à l'arrêt. Au plus une tête par seconde.

#### Export et commandes

- `ostena core audit export --out <fichier> [--from-head N]` : export en flux, mémoire constante (pagination par clé de 500 lignes, têtes fusionnées par seq couvert, ordre des trames contrôlé à l'écriture), dans un instantané `REPEATABLE READ` en lecture seule ; fichier créé en mode 0600, jamais écrasé ; puis `audit.exported`.
- `ostena core audit head` : la dernière tête, sous forme texte, à conserver hors du bastion.
- `ostena core audit verify --key <clé publique>…` : vérification de toute la chaîne dans la base, mêmes codes de sortie que `ostena audit verify`.
- `ostena core audit acknowledge-break --seq N` : acquittement d'une rupture.

Procédure d'exploitation : [vérification de l'audit](../exploitation/audit-verification.md).

#### Codes du core

`CORE-E010` (écriture d'audit impossible) et `CORE-E011` (chaîne d'audit incohérente), dans la table de l'ADR-0011.

### Suite : audit scellé (jalon M2, lot L6)

Le lot L6 complète la chaîne : stockage en ajout seul des fichiers qu'elle scelle, horodatage des têtes, export vers un SIEM, file de l'agent quand le core est injoignable. Chaque partie arrive dans sa PR (11a, 11b…) et s'ajoute ici.

#### Stockage en ajout seul des fichiers scellés (PR 11a)

Jusqu'ici, un transcript scellé n'était protégé que par ses droits (0400) et par son empreinte dans la chaîne : le compte du service, ou une erreur, pouvait le tronquer, le réécrire ou le supprimer, ce que seule la vérification révélait.

- **Attributs Linux** (`ostena_platform::worm`) : à sa création, le fichier est ouvert en ajout (`O_APPEND`), avec ses droits définitifs (0400 : le descripteur reste inscriptible), puis marqué **ajout seul** (`chattr +a`) : il ne peut plus être tronqué, réécrit, renommé ni supprimé, seulement allongé par le descripteur du core. Au scellement, après la synchronisation, il devient **immuable** (`chattr +i`) : plus aucune modification, ni contenu, ni droits, ni nom.
- **Réglage** : `[core.audit] worm`, `"required"` par défaut ; il vaut pour tous les fichiers scellés (transcripts, puis enregistrements RDP, PR 14). Au démarrage, le core vérifie avec un fichier sonde que le répertoire des transcripts le permet (Linux, système de fichiers qui gère ces attributs : ext4, XFS, Btrfs, tmpfs ; capacité `CAP_LINUX_IMMUTABLE` du service) ; sinon il refuse de démarrer (`REC-E006`). `"disabled"` revient aux seuls droits : affaiblissement `CFG-P024`, refusé en production, journalisé en développement.
- **Sceau** : `transcript.sealed` porte le champ booléen `immutable`, lu sur le disque après le scellement (jamais supposé). Un auditeur sait ainsi quels fichiers étaient protégés.
- **Reprise** : un fichier laissé en ajout seul par un arrêt du core est scellé immuable au démarrage suivant ; si le réglage est passé à `"disabled"` entre-temps, l'attribut est retiré et le fichier passe en lecture seule.
- **Pas de nouvelle dépendance** : les appels `FS_IOC_GETFLAGS` et `FS_IOC_SETFLAGS` passent par `libc`, déjà utilisée par `ostena-platform`, seule crate où le code `unsafe` est admis (commentaires `// SAFETY:` et tests).
- **Hors Linux** : pas d'équivalent ; le core ne tourne que sous Linux.

Limites : ces attributs n'arrêtent pas un compte qui détient lui-même `CAP_LINUX_IMMUTABLE` (root, ou le service, qui en a besoin pour les poser) : il peut les retirer. Ils protègent contre tout autre compte et contre les erreurs, et la chaîne d'audit reste la preuve d'intégrité. Un stockage WORM matériel ou un objet verrouillé hors du bastion reste le moyen d'une protection contre root. La rétention n'est pas automatisée : supprimer un transcript demande de retirer l'attribut à la main (procédure d'exploitation).

#### Horodatage RFC 3161 des têtes (PR 11b)

Une tête signée prouve l'intégrité de ce qu'elle couvre, pas sa date : celui qui détient la clé de signature peut réécrire la chaîne et signer de nouvelles têtes à la date qu'il veut. Un jeton d'horodatage d'un tiers (RFC 3161) sur le hash d'une tête prouve que cette tête existait à cette heure.

- **Réglage** : section `[core.audit.timestamping]`, absente par défaut (pas d'horodatage) : `url` (`http://hôte[:port]/chemin`, sans identifiants ni fragment), `ca` (fichier PEM des ancres de l'autorité, 16 au plus, lu au démarrage : un fichier illisible refuse le démarrage), `interval_secs` (600 par défaut, 60 à 86400), `timeout_secs` (10 par défaut, 1 à 60). L'absence de la section n'affaiblit rien de ce qui existait : elle n'est pas une dérogation.
- **Cadence** : à chaque intervalle, le core horodate la dernière tête si elle a changé depuis le dernier jeton. Comme le battement produit une tête même sans activité, cela revient à un jeton par intervalle : une preuve de fraîcheur datée par un tiers.
- **Demande** (RFC 3161, section 2.4.1) : empreinte SHA-256 de la tête, nonce aléatoire de 64 bits, `certReq` vrai. Transport HTTP (section 3.4) : un `POST` `application/timestamp-query`, réponse 200 de 16 Kio au plus, avec un délai.
- **Contrôle avant écriture** : statut accordé, nonce et empreinte identiques à la demande, puis le jeton entier comme le vérificateur (ci-dessous). Un jeton refusé n'est jamais écrit.
- **Profil du jeton** (`ostena_crypto::tsp`, décodeur DER strict sans dépendance de décodage) : `SignedData` à un seul signataire, `TSTInfo` v1 ; empreintes SHA-256 seulement (imprint, attribut `messageDigest`) ; signature ECDSA P-256 / SHA-256 sur les attributs signés ; attribut `signingCertificateV2` (RFC 5816) obligatoire, empreinte SHA-256 du certificat signataire, qui doit être celui désigné par `sid` ; certificat signataire porté par le jeton ou présent parmi les ancres ; usage étendu `id-kp-timeStamping` seul et critique (RFC 3161, section 2.3) ; chaîne vers une ancre de `ca`, valide à `genTime`, contrôlée par `rustls-webpki`. Les algorithmes ne sont pas négociés : un jeton d'une autre famille est refusé (`TSP-E003`).
- **Enregistrement** : `audit.head_timestamped` (classe « au mieux », par la file de l'enregistreur) porte `head_no`, `head_hash`, `stamped_at` (`genTime`, en ms), `policy` (OID de la politique de l'autorité) et le jeton DER découpé en champs binaires `tst_01` à `tst_24` de 256 octets (6 Kio au plus), car un champ binaire d'enregistrement en tient 256. Le jeton est dans la chaîne : il est couvert par la tête suivante, exporté sans changer le format d'export, et l'enregistrement reste vérifiable sans l'autorité.
- **Échecs** : chaque tentative manquée est journalisée (`audit.timestamp_failed`, avec son code) ; la première d'une série est aussi enregistrée dans la chaîne (`audit.timestamp_failed`, champs `code` et `reason`), la suivante réussie est journalisée (`audit.timestamp_restored`). Le core continue de fonctionner : l'horodatage ne bloque aucune opération.
- **Vérification** : `ostena audit verify --tsa-ca <pem>` (et `ostena core audit verify --tsa-ca`) contrôle chaque `audit.head_timestamped` : la tête désignée doit avoir été lue (parmi les 64 dernières, ou plus ancienne que la dernière lue), avec le même hash ; le jeton est vérifié contre les ancres données, avec le même profil, et `genTime` doit être égal à `stamped_at`. Un écart est `AUD-E021` ; un jeton antérieur à sa tête (au-delà de la tolérance d'horloge et de la précision `accuracy`) est `AUD-W009`. Sans `--tsa-ca`, la forme et le lien à la tête sont vérifiés, pas le jeton. Le résumé donne le nombre de jetons, de jetons vérifiés, et le dernier horodatage (tête et heure UTC).

Codes de `ostena_crypto::tsp` et du core :

| Code | Signification |
|---|---|
| `TSP-E001` | jeton ou réponse d'horodatage mal formé (DER strict, tailles bornées, attribut obligatoire absent) |
| `TSP-E002` | horodatage refusé par l'autorité (statut et texte de l'autorité) |
| `TSP-E003` | algorithme non admis (seuls SHA-256 et ECDSA P-256 / SHA-256) |
| `TSP-E004` | signature du jeton invalide |
| `TSP-E005` | certificat de l'autorité refusé (chaîne, validité à `genTime`, usage étendu, absent) |
| `TSP-E006` | jeton étranger à la demande (empreinte ou nonce) |
| `TSP-E007` | autorité injoignable ou hors protocole (connexion, délai, statut HTTP, taille) |

Choix :

- **Dans la chaîne plutôt qu'en trame d'export** : la place réservée prévoyait une trame de type 3. Un enregistrement évite une migration (le jeton n'a pas de table), garde un seul format d'export, et met le jeton sous la protection de la chaîne. Le découpage en 24 champs est le prix de la limite de 256 octets par champ binaire, sans changer le format d'enregistrement v1.
- **HTTP sans TLS** : la demande ne porte qu'une empreinte, la réponse est signée et entièrement vérifiée. Un intermédiaire ne peut que faire échouer un horodatage, ce qui se voit (`audit.timestamp_failed`), jamais en faire accepter un faux. C'est le transport de la RFC 3161, et celui des autorités courantes.
- **Nouvelle dépendance** : `rustls-webpki` devient une dépendance directe de `ostena-crypto` (déjà présente par `rustls`, même version, ISC) pour la validation de la chaîne de l'autorité avec l'usage étendu `id-kp-timeStamping`. Le client HTTP est celui de `hyper`, déjà présent (fonctionnalité `client` ajoutée au core).
- **En CI et hors ligne** : une autorité de test (`ostena_crypto::tsp::testing::TestTsa`, fonctionnalité `testing`) produit de vrais jetons ; le test du core la sert en HTTP sur la boucle locale. L'analyseur des réponses a ses tests `proptest` et sa cible de fuzzing `tsp_response`, dont le corpus est rejoué en test.

Limites : l'autorité doit signer en ECDSA P-256 / SHA-256 ; une autorité RSA est refusée (`TSP-E003`). La révocation du certificat de l'autorité (CRL, OCSP) n'est pas contrôlée : l'auditeur choisit ses ancres et peut les retirer. Un horodatage prouve qu'une tête existait à une heure, pas qu'elle n'a pas été remplacée ensuite : il faut conserver les exports, ou les têtes horodatées, hors du bastion.

#### Export syslog TLS en OCSF (PR 11c)

La chaîne est la preuve ; un SIEM en reçoit une copie, en continu, pour la corrélation et l'alerte.

- **Réglage** : chaque `[[audit.outputs]]` du fichier de configuration du core est un collecteur : `kind = "syslog"`, `address = "hôte:port"`, `transport = "tls"` (défaut), et une table `tls` : `ca` (lot PEM des autorités du collecteur, seule confiance), `server_name` (nom attendu dans son certificat, l'hôte de `address` par défaut), et pour l'authentification mutuelle `certificate` (chaîne PEM du core) avec `private_key` (clé ECDSA P-256, credential systemd seulement). Les incohérences de `tls` sont refusées à la validation (`CFG-V021`). Au démarrage, le core refuse toute autre sortie d'audit (fichier, sortie standard, syslog en clair ou sans `tls`) et lit les lots et clés avant d'écrire quoi que ce soit (`CORE-E007`, `CORE-E006` pour une clé illisible). Sans sortie, rien ne change.
- **Transport** (RFC 5425) : TLS 1.3 sur TCP, profil figé du tunnel (`ostena_crypto::tls::syslog`, ADR-0009 : `TLS_AES_256_GCM_SHA384`, `SecP256r1MLKEM768`, ECDSA P-256), trames à comptage d'octets (`MSG-LEN SP SYSLOG-MSG`).
- **Message** (RFC 5424) : facilité 13 (*log audit*), sévérité selon l'issue (succès : 6, refus : 5, échec : 4), heure de l'enregistrement (RFC 3339, millisecondes, UTC), `HOSTNAME` de la machine, `APP-NAME` `ostena`, `MSGID` `audit`, pas de données structurées, et l'événement OCSF en JSON comme `MSG`. Le JSON est en ASCII (tout autre caractère échappé en `\uXXXX`) : pas de BOM.
- **Événement OCSF** (schéma 1.3.0), un par enregistrement, classe *Base Event* :

| Champ OCSF | Valeur |
|---|---|
| `class_uid`, `category_uid`, `activity_id`, `type_uid` | 0, 0, 99 (*Other*), 99 |
| `message`, `metadata.event_code` | nom de l'événement (`agent.enrolled`…) |
| `metadata.uid` | `<chaîne>:<seq>`, unique : un collecteur écarte un doublon par ce champ |
| `metadata.correlation_uid`, `metadata.sequence` | identifiant de chaîne, seq |
| `metadata.product` | `Ostena`, version du binaire ; `metadata.log_name` : `audit` ; `metadata.version` : `1.3.0` |
| `time` | heure de l'enregistrement (ms) |
| `severity_id` | succès 1 (*Informational*), refus 3 (*Medium*), échec 4 (*High*) |
| `status_id`, `status`, `status_detail` | 1 *Success* ou 2 *Failure* ; `success`, `refused` ou `failure` |
| `actor.user.name`, `actor.user.type_id` | acteur ; utilisateur 1, administrateur 2, core 3 (*System*), agent et pair 99 (`type` : `Agent`, `Peer`) |
| `unmapped` | tous les champs de l'enregistrement, sous leur nom ; binaires en hexadécimal, UUID en texte |

  Les événements sont tous dans la classe générique : les classer par famille OCSF (authentification, activité d'API…) est une évolution possible, sans changement du transport.
- **Livraison au moins une fois** : le core envoie la chaîne dans l'ordre, par lots de 256, et lit la suite chaque seconde. La **position** d'un collecteur (dernier seq écrit et vidé vers lui) est elle-même un enregistrement de la chaîne, `audit.forwarded` (champs `destination` et `last_seq`, au mieux), au plus une fois par minute et seulement si d'autres enregistrements ont été envoyés depuis. Au démarrage et après chaque connexion perdue, l'envoi reprend après la dernière position : au pire, une minute d'enregistrements arrive deux fois, rien ne manque. Une nouvelle destination reçoit toute la chaîne depuis le seq 1. Pas de migration : la position se relit dans `audit_record` par son index d'événement.
- **Échecs** : un collecteur injoignable ou qui refuse la poignée de main (`SYS-E001`), une connexion perdue pendant l'envoi (`SYS-E002`) : journalisés à chaque tentative (`audit.forward_failed`), enregistrés une fois par série (`audit.forward_failed`, champs `destination`, `code`, `reason`), le retour journalisé (`audit.forward_restored`). Nouvelle tentative après 1 s, puis un délai doublé jusqu'à 60 s. L'export ne bloque aucune opération du core.
- **Lecture des trames** : `ostena_audit::siem` écrit les messages et relit strictement trames et en-têtes RFC 5424 (`FrameDecoder`, `parse_message`, code `AUD-E022`), pour les tests et pour qui contrôle ce qu'un collecteur a reçu. Tests de propriétés et cible de fuzzing `syslog_frame`, dont le corpus est rejoué en test.

Limites : RFC 5425 n'a pas d'accusé de réception applicatif ; « écrit et vidé » ne prouve pas la réception, d'où la reprise après la position et le dédoublonnage par `metadata.uid`. Un message peut dépasser 8 Kio (jusqu'à 64 Kio pour un enregistrement de 8 Kio aux champs binaires) : le collecteur doit accepter des messages de cette taille. Le collecteur doit proposer `SecP256r1MLKEM768` et un certificat ECDSA P-256 (par exemple OpenSSL 3.5 ou plus récent côté collecteur). Les têtes elles-mêmes ne sont pas envoyées au SIEM (elles restent dans le journal technique, `audit.head_signed`) ; la révocation du certificat du collecteur n'est pas contrôlée. Le débit est borné par la lecture (256 enregistrements par aller-retour) : largement au-dessus du rythme d'écriture de la chaîne.


#### File chiffrée des bilans de session de l'agent (PR 11d)

Le bilan d'une session (`session_closed` : raison, octets dans chaque sens) fait passer `access_session` à l'état clos et écrit `access.session_closed`. Jusqu'ici il était envoyé une fois : perdu si le core était injoignable au-delà de la grâce, ou si l'agent redémarrait. Il passe désormais par une file sur l'agent.

- **Accusé de réception** : chaque bilan porte un numéro (`report_id`) et l'heure de fin (`closed_at`, secondes Unix). Le core l'applique, puis répond `report_ack`. L'agent garde le bilan jusqu'à cet accusé et renvoie toute la file à chaque connexion, puis toutes les 30 s ce qui reste sans réponse. Le core applique un bilan une fois : un renvoi d'une session déjà close est acquitté sans rien changer. L'heure de fin est celle de l'agent, bornée par l'heure du core et jamais avant l'ouverture : un bilan arrivé tard garde l'heure réelle de la fin.
- **Chiffrée** : la file (`reports.queue`, dans le répertoire du journal anti-rejeu) est une seule enveloppe AES-256-GCM (`ostena-crypto`, donnée associée `ostena-report-queue-v1`), sous une clé propre à la file (`reports.key`, 32 octets tirés au premier démarrage, droits privés comme la clé de l'agent). Chaque changement réécrit le fichier de façon atomique (fichier privé, synchronisé, renommé). Une clé d'une autre longueur arrête le démarrage.
- **Bornée, sans perte silencieuse** : 1 024 bilans au plus. Un bilan qui ne tient pas est écarté, journalisé aussitôt (`agent.report_queue_full`, erreur) et compté. Le compte, avec le premier et le dernier instant, part vers le core comme un bilan (`reports_lost`), avant les bilans gardés. Le core l'écrit dans la chaîne (`agent.reports_lost`, champs `agent_id`, `lost_count`, `first_ms`, `last_ms`, `complete`), puis l'acquitte : l'avis n'est retiré qu'une fois écrit. Un bilan écarté pendant que l'avis est en route part dans un avis suivant. Un fichier illisible (altéré, autre clé) est mis de côté (`reports.queue.corrupt-<horodatage>`, `agent.report_queue_unreadable`) et signalé de la même façon, nombre inconnu (`complete` faux). Un échec d'écriture du fichier est journalisé (`agent.report_queue_write_failed`) : la file reste en mémoire et part dès que le lien le permet.
- **Protocole** : la version reste 1 (ajouts de messages et de champs, agent et core livrés ensemble ; ADR-0008).

Cette file est la seule donnée de session gardée sur le disque de l'agent ; les transcripts n'y sont jamais écrits (ADR-0016). Elle ne contient que le bilan (identifiant de session, raison bornée à 128 caractères, octets, heure), pas de secret.

Limites : la clé est à côté de la file, sur la même machine : le chiffrement protège une copie du fichier seul ou une sauvegarde, pas un administrateur de l'agent. La livraison est au moins une fois : un redémarrage entre l'écriture d'un avis par le core et son accusé peut l'écrire deux fois. `access.session_closed` reste de classe « au mieux » : l'accusé suit la mise à jour d'`access_session`, pas l'écriture de l'événement, dont la perte est comptée par `audit.events_lost`.

## Conséquences

- Un auditeur vérifie un export avec un binaire `ostena` et la clé publique, hors ligne, sans secret. Les décodeurs font quelques centaines de lignes sans dépendance, couverts par deux cibles de fuzzing (`audit_decode`, `audit_verify`) dont les corpus sont rejoués en test sur la toolchain stable, et par un modèle de chaîne en `proptest` qui applique une altération aléatoire à chaque export.
- Le format n'est pas un standard : un outil tiers l'implémente d'après cet ADR. Toute évolution passe par une nouvelle version, et les versions inconnues sont refusées.
- **Risques acceptés** :
  - **Troncature** : supprimer la fin de la chaîne et les têtes qui la couvrent donne un export cohérent. Elle n'est détectable qu'avec une copie externe d'une tête plus récente (`AUD-E013`) ou par la fraîcheur (`AUD-W004`, dernière tête trop ancienne au moment de l'export). Les procédures d'exploitation devront prévoir la sortie régulière de têtes hors du core.
  - **Core compromis** : celui qui contrôle le core et sa clé de signature peut réécrire toute la partie de la chaîne qui n'est pas encore couverte par une tête sortie du core. Aucun mécanisme interne (HMAC compris) n'y remédie ; seules les têtes externes et l'horodatage par un tiers (PR 11b) le bornent.
  - **Signatures classiques à longue durée de vie** : une tête doit rester vérifiable des années. ECDSA P-256 n'est pas résistant à un ordinateur quantique ; la question sera réexaminée avec les têtes hybrides ML-DSA-65 (ADR-0009). Une falsification future exigerait de casser la clé publique, et un horodatage RFC 3161 antérieur à cette date la rendrait visible.
  - **SHA-256 et pas SHA-384** : le guide ANSSI recommande des empreintes d'au moins 384 bits si une sécurité post-quantique est visée (ADR-0009). SHA-256 est retenu pour rester aligné sur ECDSA P-256 / SHA-256 et sur les grants ; un passage à SHA-384 se ferait avec une nouvelle version des enregistrements et des têtes.
- Le code `AUD-E004` couvre aussi une erreur de lecture du fichier ; la commande la distingue par son code de sortie 3.
- **Coût pour l'enrôlement** : l'enregistrement accordant ajoute environ 0,5 ms à l'écriture d'un enrôlement ou d'un renouvellement (mesure locale, PostgreSQL 16 en conteneur : 5,1 ms au lieu de 4,5 ms, la synchronisation du `COMMIT` dominant). La signature d'une tête ne se fait pas sur ce chemin, mais elle tient le verrou le temps du contrôle du segment (7,5 ms pour 600 enregistrements), ce que la cadence borne par `head_max_records`.
- **Effacement complet** : un administrateur de la base peut vider les deux tables. Le core refuse alors toute opération accordante jusqu'à son redémarrage, qui crée une nouvelle chaîne (identifiant différent, `audit.chain_started` en avertissement). Cet effacement n'est prouvé que par les têtes conservées hors du bastion (autre identifiant de chaîne, `AUD-E005` ou `AUD-E013`) ou par l'identifiant de chaîne que l'auditeur a noté. Un durcissement est noté dans les points à trancher (état conservé hors de la base).
- **Troncature vue de l'intérieur** : le contrôle du core part de la dernière tête présente en base. Une troncature qui supprime aussi les têtes qui couvraient la fin passe ce contrôle ; seules les têtes externes et la fraîcheur la révèlent, d'où la procédure de copie des têtes hors du bastion. Une troncature sous la dernière tête (enregistrements supprimés, tête conservée) est une rupture, qui ne peut être acquittée qu'une fois la chaîne repassée au-delà du seq couvert par cette tête.
