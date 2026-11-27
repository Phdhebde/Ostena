# ADR-0021 : Identités multi-sources

- **Statut** : Proposé (jalon M2, PR 9, lot L3)
- **Date** : 2026-11-26

## Contexte

Jusqu'ici, le core ne connaît que des comptes locaux (ADR-0010) : un nom, un mot de passe PBKDF2 et un TOTP, administrés par `ostena core user …`. Les clients ont déjà leurs annuaires (Active Directory, souvent en plusieurs forêts, OpenLDAP, FreeIPA) et attendent que le bastion s'y adapte, pas l'inverse. Ce que l'annuaire décide doit s'appliquer vite : un compte désactivé dans AD perd ses accès et voit ses sessions coupées **en moins de 60 s**.

Contraintes :

- LDAPS seulement : ni LDAP en clair ni StartTLS, refusés à la configuration ;
- toute la cryptographie passe par `ostena-crypto` (ADR-0009) ; les annuaires du client ne proposent ni ML-KEM ni, pour les plus anciens, TLS 1.3 ;
- deux annuaires actifs à la fois ne fusionnent jamais leurs utilisateurs : le même identifiant dans deux sources donne deux identités ;
- le core reste utilisable quand un annuaire tombe : des comptes locaux de secours restent joignables ;
- un message LDAP est une entrée réseau non fiable : analyseur borné et *fuzzable* ;
- peu de dépendances, aucune dépendance réseau au build.

## Décision

### Client LDAP : une crate maison, `ostena-ldap`

Un client LDAPv3 minimal, sans dépendance hors de l'espace de travail (tokio, thiserror, zeroize), qui s'exécute sur n'importe quel flux : le core lui passe le flux TLS ouvert par `ostena-crypto`.

- **Sous-ensemble BER strict** : étiquettes sur un octet, longueurs définies sur quatre octets au plus (la forme `0x84` d'Active Directory est admise), entiers bornés, message de 4 Mio au plus, 200 000 entrées au plus par recherche.
- **Opérations** : liaison simple, recherche paginée (contrôle `1.2.840.113556.1.4.319`, 500 entrées par page), abandon de connexion (*unbind*), avis de déconnexion. Les références (*referrals*) sont ignorées : le core ne suit jamais une adresse que l'annuaire lui donne.
- **Liaison** : un nom ou un mot de passe vide est refusé avant tout envoi (`LDAP-E008`). Un mot de passe vide ferait une liaison non authentifiée, qu'Active Directory accepte comme un succès. Le tampon qui porte le mot de passe est dimensionné une fois et effacé (`zeroize`) après l'envoi.
- **Filtres** : construits en arbre, jamais par concaténation, si bien qu'un identifiant saisi ne peut pas injecter de filtre. Les filtres de la configuration (`user_filter`) sont lus par un analyseur RFC 4515 strict.
- **Fuzzing** : deux cibles, `ldap_message` (décodeur des réponses) et `ldap_filter` (analyseur de filtres), avec leurs corpus rejoués en test.
- **Serveur de test** (fonctionnalité `testing`) : un annuaire en mémoire qui répond à ce client, avec `LDAP_MATCHING_RULE_IN_CHAIN`, la règle de ET bit à bit d'AD et la pagination.

Alternative écartée : `ldap3`. Sa licence (MIT/Apache) conviendrait, mais elle tire `nom`, `lber`, `native-tls` ou un `rustls` à elle selon les fonctionnalités, et un client complet (SASL, StartTLS, référence suivie, modifications) dont le core n'utilise presque rien. Son analyseur n'a pas de cible de fuzzing dans ce dépôt, et le TLS devrait passer par `ostena-crypto` au prix d'adaptations. Le client maison fait quelque 2 000 lignes hors tests, moins que cet arbre de dépendances.

### TLS vers les annuaires : un profil de plus dans `ostena-crypto`

`ostena_crypto::tls::directory` :

- **TLS 1.3 seulement** par défaut, suite `TLS13_AES_256_GCM_SHA384` seulement, ni reprise de session ni 0-RTT ;
- groupes : `SecP256r1MLKEM768` d'abord, puis P-256 et P-384 (échange classique quand l'annuaire ne propose pas ML-KEM, ce qui est le cas des annuaires actuels) ;
- certificat et signatures de la poignée de main : RSA de 2 048 à 8 192 bits (PKCS#1 v1.5, PSS) ou ECDSA P-256, comme le profil des cibles RDP ;
- validation : chaîne vers le seul fichier d'autorités de la source (`ca_bundle`), nom du serveur exigé, aucune autorité système.

C'est un écart au profil du tunnel, consigné dans l'ADR-0009 (« Annuaires LDAPS ») et accepté par le responsable du projet le 2026-11-26.

**TLS 1.2, option par source.** Par défaut, un annuaire qui ne propose que TLS 1.2 (Active Directory sur Windows Server 2016 ou 2019) est refusé (`IDN-E002`, « TLS 1.3 non proposé par le serveur »). `tls_min_version = "1.2"` l'admet pour une source, et pour elle seule :

- TLS 1.3 reste proposé en premier et retenu quand l'annuaire le parle ;
- en TLS 1.2 : suites ECDHE AES-256-GCM seulement (`TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384`, `TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384`), *extended master secret* exigé, mêmes groupes, signatures et validation qu'en TLS 1.3 : le profil TLS 1.2 des cibles RDP ;
- écart accepté, admis en production : `CFG-P021` journalisé et écrit dans l'audit à chaque démarrage, avertissement `identity.tls12` (source, serveur) à chaque connexion qui négocie TLS 1.2.

### Sources et noms

```toml
[core.identity]
default_source = "corp"        # nom nu : cette source ; absent : compte local
check_interval_secs = 20       # contrôle des utilisateurs connectés, 5 à 50
sync_interval_secs = 900       # passe complète, 60 à 86 400

[[core.identity.ldap]]
name = "corp"
kind = "active-directory"      # ou "openldap", "freeipa"
servers = ["ldaps://dc01.corp.example", "ldaps://dc02.corp.example:636"]
ca_bundle = "/etc/ostena/corp-ca.pem"
# tls_min_version = "1.2"     # TLS 1.2 admis (écart accepté, CFG-P021) ; défaut "1.3"
bind_dn = "CN=svc-ostena,OU=Services,DC=corp,DC=example"
bind_password = { credential = "corp-ldap.password" }
user_base = "OU=Utilisateurs,DC=corp,DC=example"
suffixes = ["corp.example"]
groups = [{ directory = "CN=Admins-Bastion,OU=Groupes,DC=corp,DC=example", group = "admins" }]
```

- **Nom d'une identité** : un compte local garde son nom (`alice`) ; un utilisateur d'annuaire est `source/identifiant` (`corp/jdupont`). Le même identifiant dans deux sources donne deux utilisateurs, jamais fusionnés. La base l'impose : un nom d'annuaire commence par le nom de sa source, et `(source, external_id)` est unique.
- **Identifiant stable** : `objectGUID` (AD, en hexadécimal), `entryUUID` (OpenLDAP), `ipaUniqueID` (FreeIPA). Un renommage dans l'annuaire renomme l'utilisateur ; ses droits, sessions et enregistrements d'audit le suivent.
- **Routage** à la connexion : `source/nom` désigne la source (`local/nom` un compte local) ; `nom@suffixe` va à la source de ce suffixe ; un nom nu va à `default_source`, ou à un compte local. Un suffixe ou une source inconnus valent un nom inconnu (`AUTH-E001`). Le choix « à l'écran » du portail se ramène à la forme `source/nom`.
- **Comptes de secours** : les comptes locaux restent joignables par `local/nom` quand un annuaire est indisponible, ou quand `default_source` désigne un annuaire.
- **Bascule** : les serveurs d'une source sont essayés dans l'ordre, en commençant par le dernier qui a répondu (`identity.server_failover`). Un compte de service refusé arrête tout de suite (`IDN-E003`) : le même compte sert sur tous les serveurs, et insister le verrouillerait.
- **Secret du compte de service** : lu d'un *credential* systemd ou d'un fichier lisible du seul service (`CFG-P020` sinon), gardé dans un `SecretString`, jamais journalisé.
- **Adresses de métadonnées** : le nom d'un serveur est résolu par le core, et une adresse de métadonnées cloud du plancher de l'ADR-0005 (`169.254.169.254`, `fd00:ec2::/64`, etc.) est refusée avant toute connexion (`IDN-E002`) ; le serveur suivant est essayé.

### Connexion d'un utilisateur d'annuaire

La phase 1 de la connexion (ADR-0010) lit l'utilisateur dans sa source avec le compte de service, applique ce que dit l'annuaire au core (création, mise à jour, désactivation), puis vérifie le mot de passe par une liaison sous le nom de l'utilisateur, sur la même connexion. Elle tient un des créneaux de hachage pendant ce temps, ce qui borne les liaisons simultanées. Un compte refusé par l'annuaire n'est jamais lié. La phase 2 est celle des comptes locaux, sans empreinte stockée : compte actif, TOTP confirmé, code vérifié, session ouverte.

- Le **TOTP reste exigé** : l'annuaire donne le premier facteur, le core le second. Un utilisateur d'annuaire est enrôlé comme un compte local (`ostena core user totp-enroll`) une fois créé par la synchronisation.
- Son mot de passe est celui de l'annuaire : `ostena core user password` le refuse.
- Un annuaire injoignable donne `AUTH-E006` (le core ne peut pas décider), pas un refus.

### Synchronisation

En lecture seule, par le compte de service :

- **à chaque connexion** de l'utilisateur ;
- **toutes les `check_interval_secs`** (20 s par défaut, 50 au plus) : les utilisateurs de la source qui ont une session de connexion ouverte, relus par leur identifiant, par lots de 50 ;
- **toutes les `sync_interval_secs`** (15 min par défaut) : une passe complète, paginée, sur `user_base` et le filtre de la source.

Ce que l'annuaire refuse :

| Annuaire | Désactivé | Mot de passe changé |
|---|---|---|
| Active Directory | `userAccountControl` & 2, ou `accountExpires` passé | `pwdLastSet` |
| OpenLDAP | `pwdAccountLockedTime` présent | `pwdChangedTime` |
| FreeIPA | `nsAccountLock = TRUE` | `krbLastPwdChange` |

Un utilisateur désactivé, supprimé, sorti du filtre, ou qui n'est plus dans aucun groupe des règles (avec `require_group`, la valeur par défaut) est **désactivé** dans le core : ses sessions de connexion sont révoquées dans la même transaction. Le core prévient les agents (`Notice::LoginRevoked`, comme pour `ostena core user disable`), qui coupent les sessions, et aucun grant n'est plus émis pour lui. Un mot de passe changé dans l'annuaire révoque les sessions ouvertes avant le changement. Le délai est donc d'au plus `check_interval_secs` plus le temps d'une recherche : mesuré à 0,84 s avec un contrôle par seconde contre le serveur de test.

La source ne lève que ce qu'elle a posé : `directory_disabled` distingue une désactivation par l'annuaire d'une désactivation par un administrateur. Seule la première est levée quand l'annuaire réactive le compte (`identity.user_reenabled`). Une source injoignable ne désactive personne.

### Groupes

Chaque source porte des règles « groupe de l'annuaire → groupe d'utilisateurs du core ». Les groupes du core (`user_group`, `user_group_member`) sont créés par les règles et nourris par la synchronisation, pour la décision d'accès (PR 10).

- **Active Directory** : une recherche par règle, `memberOf:1.2.840.113556.1.4.1941:=<DN>` (`LDAP_MATCHING_RULE_IN_CHAIN`), qui suit les groupes imbriqués côté serveur.
- **OpenLDAP, FreeIPA** : lecture des groupes de `group_base` (`member`, `uniqueMember`), fermeture transitive calculée par le core, 32 niveaux au plus.

### Base (migration `0009_identity_sources`)

`app_user` gagne `source`, `external_id`, `directory_dn`, `directory_disabled` et `synced_at`, avec leurs contraintes. Les tables `user_group` et `user_group_member` sont créées. Le rôle du service reçoit `SELECT, INSERT` sur `user_group` (un groupe n'est ni modifié ni supprimé) et `SELECT, INSERT, DELETE` sur `user_group_member`. La migration descendante garde chaque utilisateur d'annuaire comme compte local désactivé nommé `source.identifiant`, pour que ses sessions, droits et enregistrements d'audit le désignent toujours.

### Événements d'audit

| Événement | Classe | Quand |
|---|---|---|
| `identity.user_provisioned` | accordant | utilisateur créé depuis sa source |
| `identity.user_reenabled` | accordant | utilisateur réactivé par sa source |
| `user.disabled` | protecteur | désactivé par sa source (motif : `reason`, source : `identity_source`) |
| `login_session.revoked` | protecteur | session révoquée par la source (`revoked_by` `core:identity/<source>`) |
| `user_group.created` | accordant | groupe d'utilisateurs créé par une règle |
| `user_group.member_added` | accordant | appartenance donnée par une règle |
| `user_group.member_removed` | protecteur | appartenance retirée |
| `identity.sync_completed` | au mieux | passe complète : vus, créés, mis à jour, désactivés, sessions révoquées, durée |
| `identity.source_unavailable` | au mieux | la source ne répond plus (code `IDN-…`) |
| `identity.source_restored` | au mieux | la source répond de nouveau |

Champs nouveaux : `identity_source`, `user_group`, `directory_dn`, `server`, `users_seen`, `users_created`, `users_updated`, `users_disabled`, `duration_ms`.

### Codes

| Code | Sens |
|---|---|
| `IDN-E001` | aucun serveur de la source ne répond (connexion, délai, ou TLS refusé par tous) |
| `IDN-E002` | serveur refusé : autorité, nom, TLS 1.2 seulement (sans l'option), suite ou groupe hors profil, adresse de métadonnées cloud |
| `IDN-E003` | compte de service refusé |
| `IDN-E004` | recherche en échec |
| `IDN-E005` | source inutilisable : fichier d'autorités, filtre, adresse |
| `LDAP-E001` à `LDAP-E009` | client LDAP : message mal formé, trop long, connexion interrompue, réponse inattendue, opération refusée (avec le code LDAP), avis de déconnexion, trop d'entrées, liaison sans nom ou sans mot de passe, filtre invalide |
| `CORE-E015` | source d'identités inutilisable (porte le code `IDN-…`) |
| `CFG-V020` | section `[core.identity]` invalide (ADR-0003) |
| `CFG-P020` | mot de passe d'une source lisible au-delà du service (ADR-0003) |
| `CFG-P021` | TLS 1.2 admis vers les annuaires d'une source, écart accepté, journalisé à chaque démarrage (ADR-0003, ADR-0009) |

Journal seul (pas d'audit) : `identity.tls12`, avertissement à chaque connexion d'une source qui négocie TLS 1.2 ; `identity.server_failover`, bascule vers un autre serveur.

### Tests

- Serveur LDAP de test servi en TLS 1.3 par une PKI de test : deux annuaires à la fois, même identifiant dans deux sources, groupes imbriqués des deux sortes, bascule, LDAP en clair refusé sans qu'aucune liaison parte, autorité étrangère, autre nom, TLS 1.2 refusés, TLS 1.2 admis avec l'option, compte de service refusé.
- Sur PostgreSQL : création, connexion d'un utilisateur d'annuaire avec TOTP, désactivation coupée en moins de 60 s, suppression, sortie des groupes, désactivation par un administrateur jamais levée, mot de passe changé.
- De bout en bout, chaque nuit, contre l'AD du laboratoire (ADR-0025, `identities-lab.yml`) : lecture en TLS 1.3, liaison, compte désactivé vu en moins de 60 s, refus du port 389 et d'une autre autorité.

## Conséquences

- Le bastion se branche sur plusieurs annuaires sans fusionner leurs comptes. Les comptes locaux restent le recours quand les annuaires tombent.
- La coupure en moins de 60 s coûte une recherche par source toutes les 20 s, limitée aux utilisateurs connectés, plus une passe complète tous les quarts d'heure.
- **Écart TLS**, accepté (ADR-0009) : échange de clés classique et certificats RSA vers les annuaires, et TLS 1.2 (ECDHE, AES-256-GCM, EMS) pour les seules sources qui l'admettent. Une source TLS 1.2 se voit dans les journaux à chaque démarrage et à chaque connexion.
- **Pas de contrôle de périmètre complet** (ADR-0005) sur les serveurs d'annuaire : ce sont des adresses de la configuration, pas d'une cible ni d'un grant, et la connexion vient du core. Seules les adresses de métadonnées cloud du plancher sont refusées. À reconsidérer si une source pouvait être désignée par un utilisateur.
- Un client LDAP maison est à maintenir. Il est petit, sans dépendance et fuzzé, mais il ne parle que le sous-ensemble utile : pas de SASL (Kerberos, GSSAPI), pas d'écriture dans l'annuaire, pas de référence suivie.
- Le TOTP reste administré dans le core, utilisateur par utilisateur. Un second facteur venu de la source (attribut, OIDC) fera l'objet d'un autre ADR.
- Les groupes du core existent avant la décision d'accès qui les lira (PR 10).
