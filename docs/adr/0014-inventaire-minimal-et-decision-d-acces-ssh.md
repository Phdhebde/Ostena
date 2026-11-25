# ADR-0014 : Inventaire minimal et décision d'accès SSH du core

- **Statut** : Accepté. Implémenté dans le lot M1, PR 5b.
- **Date** : 2026-11-25

## Contexte

Le parcours SSH natif est décrit dans l'ADR-0010 et ses messages dans l'ADR-0008. Jusqu'ici, seul le core de test (`ostena_tunnel::testing`) y répondait. Le core réel doit maintenant :
- tenir un inventaire : groupes de passerelles, utilisateurs, ressources, comptes, droits ;
- décider d'un accès et signer le grant v2 (ADR-0004) ;
- certifier la clé d'hôte SSH des agents ;
- pousser aux agents la politique de périmètre, le jeu de clés de grant et la confiance SSH ;
- diffuser la révocation d'une session de connexion.

Le but du jalon M1 est un inventaire **minimal**, administré en ligne de commande. Les identités multi-sources, l'API et le portail viendront ensuite. La connexion de l'utilisateur (`ostena login`, émission du certificat utilisateur) appartient à la PR 7.

## Décision

### Schéma (migration `0003_access_inventory`)

| Table | Contenu | Bornes |
|---|---|---|
| `gateway_group` | nom, noms d'hôte SSH, politique de périmètre et sa version | nom `[a-z0-9][a-z0-9._-]{0,62}` ; 16 noms d'hôte au plus ; politique de 1 Mio au plus |
| `app_user` | nom de connexion, nom affiché, état | nom `[a-z0-9][a-z0-9._-]{0,63}` ; `active` ou `disabled` |
| `login_session` | utilisateur, SHA-256 du certificat, début, fin, révocation | 8 h au plus ; certificat unique |
| `resource` | nom, hôte, port, clé d'hôte SSH épinglée, groupe | nom `[a-z0-9][a-z0-9.-]{0,62}` ; clé P-256 de 65 octets |
| `target_account` | ressource, nom du compte | 1 à 256 octets ; unique par ressource |
| `access_right` | utilisateur, compte, protocole, début, **fin obligatoire**, durée maximale de session, révocation | 366 jours au plus ; session de 60 s à 12 h |
| `grant_key`, `grant_key_set` | clés de signature des grants (kid, clé publique, activation, retrait) ; version du jeu | |
| `access_grant` | grants émis, par jti : session de connexion, droit, agent, groupe, ressource, compte, durée, émission, expiration, consommation | jti de 16 octets |
| `access_session` | sessions ouvertes et leur fin | |
| `agent_ssh` | clé d'hôte SSH de chaque agent, son certificat, la version de confiance poussée | |

- **Une seule séquence `push_version`** versionne le jeu de clés, les politiques et la confiance SSH. Une version poussée ne recule donc jamais, même après une suppression ou une restauration partielle.
- Les contraintes sont aussi en base (`CHECK`) : une erreur de code ne crée pas un droit sans fin.

### Administration (`ostena core …`)

| Commande | Effet |
|---|---|
| `group add <nom> [--id <uuid>] [--host-name <nom>]…` | crée un groupe ; `--id` reprend l'UUID donné à `agent token --group` |
| `group host-names <nom> [--host-name <nom>]…` | remplace les noms d'hôte SSH du groupe |
| `group policy <nom> <fichier.toml>` | politique de périmètre : les champs d'une entrée `[[scope.policies]]` de l'agent, compilée comme en production avant d'être enregistrée ; affiche sa version |
| `group list` | groupes, noms d'hôte, version de politique |
| `user add <nom> --display-name <texte>` | crée un utilisateur |
| `user list` | utilisateurs et état |
| `user disable <nom>` | désactive l'utilisateur et révoque ses sessions de connexion |
| `resource add <nom> --host <hôte> [--port 22] --group <groupe> --host-key <ssh_host_ecdsa_key.pub>` | ajoute une ressource ; la clé d'hôte est lue dans le fichier public de la cible |
| `resource list` | ressources, adresse, groupe, clé épinglée, comptes |
| `account add --resource <ressource> <compte>` | ajoute un compte |
| `right grant --user --resource --account --days <1–366> [--max-session-mins 60]` | accorde un droit SSH ; `--days` est obligatoire |
| `right list`, `right revoke <uuid>` | liste, révocation |
| `login revoke <uuid> --reason <texte>` | révoque une session de connexion |
| `access check --user --resource --account` | **essai à blanc** de la décision, sans session de connexion ; rien n'est écrit, pas même dans la chaîne d'audit ; code de sortie 1 en cas de refus |

Comme pour les agents (ADR-0011), une commande agit sur la base pendant que le core tourne ; elle le notifie sur le canal `ostena_registry` (`login_revoked:<id>`, `group:<id>`) et il applique le changement tout de suite. Une requête d'administration invalide est refusée par `CORE-E012`.

**Classes d'audit** (ADR-0012) :
- **accordant** : `gateway_group.updated`, `user.created`, `resource.created`, `target_account.created`, `right.granted` ; sans enregistrement, le changement est refusé (`CORE-E010`) ;
- **protecteur** : `user.disabled`, `right.revoked`, `login_session.revoked` ; le changement est validé même si l'enregistrement échoue. La révocation et la désactivation sont idempotentes : seule la première est auditée. Une désactivation répétée révoque seulement les sessions de connexion encore valides, s'il en reste (chacune auditée par `login_session.revoked`, sans second `user.disabled`).

### Décision d'un accès SSH

À `ssh_grant_request`, dans **une seule transaction** :
1. `[core.ssh]` absent : `ACC-E007` ;
2. la session de connexion est lue et verrouillée (`FOR SHARE`, après l'utilisateur, voir l'ordre des verrous) : inconnue, expirée, révoquée, ou d'un autre sujet ou d'un autre certificat (`ACC-E001` à `ACC-E004`) ;
3. l'utilisateur doit être actif (`ACC-E005`) ;
4. la ressource doit exister, appartenir au groupe de l'agent et avoir une clé d'hôte épinglée (`INV-E001`, `INV-E002`, `INV-E004`) ; le compte doit exister (`INV-E003`) ;
5. un droit SSH valide, non révoqué, est cherché pour l'utilisateur et le compte (`ACC-E006`) ;
6. le grant v2 est signé : sujet, ressource, audience (le groupe), protocole SSH, durée, **liaison à la session de connexion et au compte** (ADR-0004), TTL de 60 s. Il est enregistré par son jti avec son enregistrement d'audit accordant `access.ssh_granted`, puis renvoyé dans `ssh_grant`.

Le verrou `FOR SHARE` porte sur l'utilisateur, la session de connexion, la ressource, le compte et le droit. Une révocation concurrente attend donc que le grant soit enregistré, puis le trouve, et l'agent qui l'a reçu est prévenu.

**Ordre des verrous** : toute transaction qui verrouille plusieurs de ces lignes les prend dans cet ordre canonique : `access_grant`, `app_user`, `login_session`, `resource`, `target_account`, `access_right`. La demande de grant verrouille donc l'utilisateur avant sa session de connexion (les codes de refus restent évalués dans l'ordre ci-dessus), l'ouverture de session le grant, puis l'utilisateur, puis la session de connexion, et `user disable` l'utilisateur avant ses sessions de connexion. Sans cet ordre, une désactivation et une demande de grant simultanées pouvaient s'attendre l'une l'autre, et PostgreSQL annulait l'une d'elles (`40P01`).

**Durée maximale de la session** : le minimum de la durée du droit, du temps restant jusqu'à la fin du droit et du temps restant jusqu'à la fin de la session de connexion.

À `session_request`, le grant est vérifié de nouveau. Son jti est verrouillé (`FOR UPDATE`) et **consommé une seule fois pour tout le groupe** (`GRT-E010` au rejeu, `GRT-E011` pour une autre audience, `ACC-E008` pour un grant inconnu du core). Tout ce dont il dépend est relu. La session est enregistrée (`access.session_opened`, accordant), et `session_params` porte le compte et la clé hôte épinglée de la cible. `session_closed` enregistre la fin (`access.session_closed`, au mieux).

**Ce qui sort d'un refus** : l'agent reçoit le code précis et son libellé générique dans `session_refused`. La raison complète va dans la chaîne d'audit (`access.ssh_refused`, `access.session_refused`, au mieux). Le client SSH ne reçoit rien de plus qu'un refus.

**Essai à blanc** (`access check`) : mêmes contrôles, depuis la base, sans signature ni écriture. Il reste hors de la chaîne d'audit : il ne change aucun droit.

### Codes

| Code | Refus |
|---|---|
| `ACC-E001` | session de connexion inconnue |
| `ACC-E002` | session de connexion expirée |
| `ACC-E003` | session de connexion révoquée |
| `ACC-E004` | sujet ou certificat différent de celui de la session de connexion |
| `ACC-E005` | utilisateur inconnu ou désactivé |
| `ACC-E006` | aucun droit valide |
| `ACC-E007` | accès SSH non configuré sur le core (`[core.ssh]`) |
| `ACC-E008` | grant inconnu du core |
| `INV-E001` | ressource inconnue |
| `INV-E002` | ressource d'un autre groupe de passerelles |
| `INV-E003` | compte inconnu sur la ressource |
| `INV-E004` | clé d'hôte de la cible non épinglée |
| `INV-E005` | aucun nom d'hôte SSH pour le groupe : pas de certificat d'hôte |
| `CORE-E012` | requête d'administration invalide |
| `CFG-V016` | deux clés du core ont la même source (ADR-0003) |

`CORE-E013` et les suivants sont réservés à la PR 7.

### Clés et autorités

- `core.grant_signing_key` : la clé P-256 qui signe les grants. Elle est **activée au démarrage** (`grant.key_activated`, accordant) si elle est nouvelle. La clé qu'elle remplace reçoit une date de retrait : maintenant, plus la durée de vie maximale d'un grant (300 s), plus la tolérance d'horloge (5 s). Le jeu poussé contient la clé active et les clés dont le retrait est postérieur à son activation, 16 au plus.
- `[core.ssh] user_ca_key` : l'autorité des certificats utilisateur. Le core en expose l'émission (`SshAuthorities::issue_user`) : principal l'utilisateur, identifiant de clé la session de connexion, 8 h au plus. Aucune commande ne l'émet : c'est le rôle du service de connexion (PR 7).
- `[core.ssh] host_ca_key` : l'autorité des certificats d'hôte des agents.
- `[core.ssh] host_certificate_days` : validité d'un certificat d'hôte, de 1 à 90 jours (30 par défaut).
- **Toutes les clés du core diffèrent** (TLS du serveur, AC émettrice, audit, grants, autorités SSH) : même source refusée à la validation (`CFG-V016`), même clé publique refusée au chargement, quel que soit le fichier.

### Poussées à la connexion d'un agent

Dans l'ordre :
1. le jeu de clés de grant ;
2. la politique de son groupe, si elle existe ;
3. sa confiance SSH, si `[core.ssh]` est configuré ;
4. `login_revoked` pour chaque session de connexion **révoquée et pas encore expirée** pour laquelle il a reçu un grant ou ouvert une session (tout agent du groupe peut consommer un grant). Un agent coupé pendant une révocation l'apprend donc à son retour, y compris après un redémarrage du core.

**Confiance SSH** : autorités d'utilisateurs et d'hôtes, et le certificat d'hôte de l'agent s'il en a un. Sa version change **seulement si son contenu change** (empreinte SHA-256 des autorités et du certificat). Une même poussée répétée garde sa version, ce que l'agent accepte (ADR-0008).

**Certificat d'hôte** : à `ssh_host_key`, le core vérifie la preuve de possession (sinon `TUN-E022`, audité au mieux, et le tunnel est fermé), puis certifie la clé (`ssh.host_certified`, accordant). Les principaux sont les noms d'hôte SSH du groupe, l'identifiant de clé l'UUID de l'agent, le numéro de série tiré au hasard. Il pousse ensuite de nouveau la confiance. Un refus est audité au mieux (`ssh.host_key_refused`). Le certificat est renouvelé après les deux tiers de sa vie : contrôle toutes les heures pour les agents connectés.

**Changement de groupe** (`group policy`, `group host-names`) : la politique est poussée de nouveau aux agents connectés du groupe, et leurs certificats d'hôte sont renouvelés avec les nouveaux noms.

**Révocation d'une session de connexion** (`login revoke`, `user disable`) : le core envoie `login_revoked` tout de suite aux agents connectés qui ont reçu un grant pour elle ou ouvert une session avec l'un de ses grants (`login_session.revocation_applied`, au mieux).

### Événements d'audit

Nouveau type d'acteur **4, utilisateur** (ADR-0012), pour les décisions prises au nom d'un utilisateur. Nouveaux événements : `grant.key_activated`, `access.ssh_granted`, `access.ssh_refused`, `access.session_opened`, `access.session_refused`, `access.session_closed`, `ssh.host_certified`, `ssh.host_key_refused`, `login_session.revoked`, `login_session.revocation_applied`, `user.created`, `user.disabled`, `resource.created`, `target_account.created`, `right.granted`, `right.revoked`, `gateway_group.updated`.

### Dépendances

`ostena-core` dépend de `ostena-ssh` **sans ses fonctions par défaut** : les certificats et les lignes de clé OpenSSH, sans la bibliothèque SSH. `cargo tree -p ostena-core -e normal` ne montre pas `russh`. S'ajoutent `ostena-grant`, `ostena-scope`, `base64` et `serde_json`, déjà dans l'arbre.

## Conséquences

- Le parcours SSH natif fonctionne avec le core réel : un test de bout en bout (`crates/ostena-core/tests/ssh_e2e.rs`) fait tourner le core avec une liaison et une passerelle d'agent. Il couvre les poussées, le certificat d'hôte, le grant et la session, un code de refus, puis la révocation, le core connecté, puis arrêté et après son redémarrage. Le test de démonstration de la CLI administre un groupe, sa politique (appliquée tout de suite par l'agent connecté), un utilisateur, une ressource, un compte et un droit.
- Un droit sans fin n'existe pas : 366 jours au plus, à renouveler.
- **Limites connues** :
  - **Un droit révoqué ne coupe pas les sessions ouvertes** : il empêche seulement tout nouveau grant. Pour couper, il faut révoquer la session de connexion ou désactiver l'utilisateur.
  - **Le jeu de clés de grant du core n'est chargé qu'au démarrage** : un changement de `grant_signing_key` demande un redémarrage. Les grants encore valides de l'ancienne clé restent acceptés, par les agents et par le core, jusqu'à sa date de retrait.
  - **La ligne `@cert-authority` porte `*`** : le client accepte cette autorité pour tout nom d'hôte. Les noms du groupe restent contrôlés par les principaux du certificat. La PR 7 construit la ligne qu'elle distribue à partir de `host_ca_public()`.
  - **Aucune commande n'émet de certificat utilisateur** : le parcours complet attend le service de connexion (PR 7). Les tests créent la session de connexion par la bibliothèque.
  - Les groupes, ressources, comptes et utilisateurs ne se suppriment pas encore ; un utilisateur se désactive.
