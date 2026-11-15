# ADR-0012 : Chaîne d'audit du core

- **Statut** : Accepté. Implémenté dans le lot M1 : format et vérificateur (PR 3a), intégration au core (PR 3b).
- **Date** : 2026-11-15

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
| 1 | type d'acteur | 0 core, 1 administrateur, 2 agent, 3 pair |
| 1 + n | acteur | UTF-8, au plus 128 octets, sans caractère de contrôle |
| 1 + n | événement | ASCII `[a-z0-9_.]`, de 3 à 64 octets |
| 1 | nombre de champs | au plus 32 |
| … | champs | longueur du nom (`u8`), nom `[a-z0-9_]` de 1 à 32 octets, **strictement croissants** octet par octet ; type (`u8`) ; longueur (`u16`) ; valeur |

Types de valeur : 1 texte (UTF-8, au plus 1024 octets, sans caractère de contrôle), 2 entier `u64` (8 octets), 3 octets (au plus 256), 4 UUID (16 octets), 5 booléen (1 octet, 0 ou 1). Aucun octet en trop, au plus 8192 octets au total.

- **Hash d'un enregistrement** : `SHA-256("ostena-audit-record-v1" ‖ 0x00 ‖ corps)`.
- **Décodeur strict** : tout ce qui n'est pas l'unique encodage canonique est refusé (`AUD-E001`), si bien que `encode(decode(b)) == b` pour tout `b` accepté. Un même événement n'a qu'une représentation, donc qu'un hash. L'absence de caractère de contrôle dans l'acteur et les textes évite aussi l'injection de séquences d'échappement dans le terminal de l'auditeur.
- **Événements** : le type `EventKind` liste les événements écrits par le core : `audit.chain_started`, `audit.signing_started`, `audit.events_lost`, `audit.break_acknowledged`, `audit.exported`, `core.started`, `core.stopped`, `core.migrated`, `core.database_not_peer`, `config.waiver`, `core.registry_unavailable`, `core.registry_restored`, `enroll.token_issued`, `enroll.token_consumed`, `enroll.token_rejected`, `agent.enrolled`, `agent.certificate_renewed`, `agent.revoked`, `agent.revocation_applied`, `agent.renewal_refused`, `tunnel.agent_connected`, `tunnel.refused`. Le décodeur accepte tout nom bien formé, pour qu'un vérificateur ancien lise une chaîne plus récente.
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

### Place réservée

- **Horodatage RFC 3161** : trame d'export de type 3, hors de la signature de la tête, portant un jeton sur le hash de tête. Une version ultérieure du vérificateur l'acceptera ; la v1 la refuse plutôt que de l'ignorer.
- **Têtes hybrides v2** : ECDSA P-256 + ML-DSA-65 par concaténation, comme prévu par l'ADR-0009 pour les têtes de chaîne d'audit, dans une tête de version 2 avec son propre algorithme. Les enregistrements ne changent pas. Bloquant : ML-DSA n'est exposé par `aws-lc-rs` que derrière une fonctionnalité instable (ADR-0009).

### Intégration au core

#### Schéma (migration `0002_audit_chain`)

- `audit_record` : `seq` (clé, au moins 1), `body` (le corps encodé, de 73 à 8192 octets : `MIN_RECORD_LEN` et `MAX_RECORD_LEN`), `hash` (32 octets), `event` (nom, pour l'index `(event, seq)`), `recorded_at`.
- `audit_head` : `head_no` (clé, au moins 1), `record_seq` (référence `audit_record`), `body` (182 octets), `hash` (32 octets), `signed_at` ; index sur `record_seq`.
- **Ajout seul** : déclencheurs `BEFORE UPDATE OR DELETE` (par ligne) et `BEFORE TRUNCATE` sur les deux tables, qui lèvent `insufficient_privilege` ; `REVOKE UPDATE, DELETE, TRUNCATE … FROM PUBLIC`.
- **Contiguïté** : un déclencheur `BEFORE INSERT` impose `seq = max + 1`, `head_no = max + 1` et une tête qui ne dépasse pas le dernier enregistrement.
- Avec le rôle unique de M1 (ADR-0011), ces protections n'arrêtent que les erreurs : le propriétaire peut désactiver un déclencheur. **L'intégrité est cryptographique** (chaînage, têtes signées, contrôle du core et `ostena audit verify`). Après la séparation des rôles, le compte du service n'aura que `SELECT` et `INSERT` sur ces tables ([note](../notes/core-roles-base.md)).

#### Écriture

- Chaque ajout prend le verrou consultatif de transaction `AUDIT_LOCK_KEY` (au-dessus de 2^62, il ne peut pas croiser celui des migrations de sqlx), lit le bout de la chaîne, le contrôle contre son contenu et insère l'enregistrement suivant. Le verrou est tenu jusqu'à la fin de la transaction : les seq suivent l'ordre des validations, sans trou.
- L'ajout est **la dernière instruction avant le `COMMIT`**, dans une transaction `READ COMMITTED`.
- La chaîne démarre au premier ajout (ou au démarrage du core) : identifiant tiré au hasard, `audit.chain_started` au seq 1, sous le même verrou, donc une seule fois même si plusieurs processus démarrent ensemble.
- L'acteur d'une commande d'administration est l'utilisateur de la base (`system_user`, `peer:<compte>` en production).

#### Classes d'échec d'écriture

| Classe | Événements | Si l'enregistrement ne peut pas être écrit |
|---|---|---|
| **Accordant** | `agent.enrolled`, `agent.certificate_renewed` (choisi d'après l'insertion de la ligne `agent`), `enroll.token_issued`, `enroll.token_consumed`, `audit.signing_started`, `core.migrated`, `config.waiver`, `core.started`, `audit.break_acknowledged`, `audit.exported` | écrit dans la transaction du changement ; l'échec l'annule et le refuse (`TUN-E029` côté tunnel, `CORE-E010` sinon) ; le core refuse de démarrer |
| **Protecteur** | `agent.revoked`, `enroll.token_rejected` (échecs, brûlage, code) | écrit dans un point de sauvegarde ; le changement est validé quand même ; l'échec est journalisé (`audit.append_failed`, niveau erreur) et compté |
| **Au mieux** | `tunnel.agent_connected`, `tunnel.refused` (agent identifié), `agent.renewal_refused`, `agent.revocation_applied`, `core.registry_unavailable`, `core.registry_restored`, `core.stopped` | file bornée de 256 événements, écrite par une seule tâche par lots (un verrou par lot), avec reprise ; les événements perdus sont comptés, puis consignés par `audit.events_lost` (nombre, premier et dernier instant) dès que la chaîne est de nouveau inscriptible. `core.stopped` est écrit de façon synchrone, en 2 s au plus |

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

## Conséquences

- Un auditeur vérifie un export avec un binaire `ostena` et la clé publique, hors ligne, sans secret. Les décodeurs font quelques centaines de lignes sans dépendance, couverts par deux cibles de fuzzing (`audit_decode`, `audit_verify`) dont les corpus sont rejoués en test sur la toolchain stable, et par un modèle de chaîne en `proptest` qui applique une altération aléatoire à chaque export.
- Le format n'est pas un standard : un outil tiers l'implémente d'après cet ADR. Toute évolution passe par une nouvelle version, et les versions inconnues sont refusées.
- **Risques acceptés** :
  - **Troncature** : supprimer la fin de la chaîne et les têtes qui la couvrent donne un export cohérent. Elle n'est détectable qu'avec une copie externe d'une tête plus récente (`AUD-E013`) ou par la fraîcheur (`AUD-W004`, dernière tête trop ancienne au moment de l'export). Les procédures d'exploitation devront prévoir la sortie régulière de têtes hors du core.
  - **Core compromis** : celui qui contrôle le core et sa clé de signature peut réécrire toute la partie de la chaîne qui n'est pas encore couverte par une tête sortie du core. Aucun mécanisme interne (HMAC compris) n'y remédie ; seules les têtes externes et l'horodatage par un tiers le bornent.
  - **Signatures classiques à longue durée de vie** : une tête doit rester vérifiable des années. ECDSA P-256 n'est pas résistant à un ordinateur quantique ; la question sera réexaminée avec les têtes hybrides ML-DSA-65 (ADR-0009). Une falsification future exigerait de casser la clé publique, et un horodatage RFC 3161 antérieur à cette date la rendrait visible.
  - **SHA-256 et pas SHA-384** : le guide ANSSI recommande des empreintes d'au moins 384 bits si une sécurité post-quantique est visée (ADR-0009). SHA-256 est retenu pour rester aligné sur ECDSA P-256 / SHA-256 et sur les grants ; un passage à SHA-384 se ferait avec une nouvelle version des enregistrements et des têtes.
- Le code `AUD-E004` couvre aussi une erreur de lecture du fichier ; la commande la distingue par son code de sortie 3.
- **Coût pour l'enrôlement** : l'enregistrement accordant ajoute environ 0,5 ms à l'écriture d'un enrôlement ou d'un renouvellement (mesure locale, PostgreSQL 16 en conteneur : 5,1 ms au lieu de 4,5 ms, la synchronisation du `COMMIT` dominant). La signature d'une tête ne se fait pas sur ce chemin, mais elle tient le verrou le temps du contrôle du segment (7,5 ms pour 600 enregistrements), ce que la cadence borne par `head_max_records`.
- **Troncature vue de l'intérieur** : le contrôle du core part de la dernière tête présente en base. Une troncature qui supprime aussi les têtes qui couvraient la fin passe ce contrôle ; seules les têtes externes et la fraîcheur la révèlent, d'où la procédure de copie des têtes hors du bastion. Une troncature sous la dernière tête (enregistrements supprimés, tête conservée) est une rupture, qui ne peut être acquittée qu'une fois la chaîne repassée au-delà du seq couvert par cette tête.
