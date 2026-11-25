# ADR-0010 : Accès SSH natif

- **Statut** : Accepté en partie. Le parcours, les clés de l'agent sur les cibles, la liste d'algorithmes et le pré-contrôle sont décidés. Ce dernier est implémenté avec la configuration de la bibliothèque (jalon M1, PR 1). Les certificats, le serveur SSH de l'agent et le driver vers les cibles sont implémentés comme bibliothèque, avec leurs messages de tunnel (jalon M1, PR 4). Le grant signe le compte et la session de connexion, et l'agent vérifie la signature de son certificat d'hôte (jalon M1, PR 5a). L'autorisation par le core (session de connexion, droit, émission du grant et des certificats) vient à la PR 5. Le serveur est lié dans l'agent, avec ses clés créées au premier démarrage et `ostena agent ssh-key` (jalon M1, PR 6). Les transcripts viennent ensuite.
- **Date** : 2026-11-13
- **Révision** : 2026-11-15, certificats, serveur, driver, codes `SSH-E010` à `SSH-E019`, événements (jalon M1, PR 4)
- **Révision** : 2026-11-25, compte et session de connexion signés par le grant (format v2), autorités d'hôtes poussées et signature du certificat d'hôte vérifiée (jalon M1, PR 5a)
- **Révision** : 2026-11-25, liaison dans l'agent, clés créées par l'agent, `ostena agent ssh-key`, code `SSH-E020`, événements `agent.ssh_*` (jalon M1, PR 6)

## Contexte

L'administrateur doit joindre une cible avec son client SSH habituel, sans plugin : `ssh root@srv-lab01@bastion`. Le bastion doit l'authentifier fortement, vérifier son droit et tracer la session, sans que l'agent passerelle détienne de base de données ni de secret partagé.

Le format des grants (ADR-0004) prévoit qu'un grant puisse transiter dans un champ de mot de passe d'un client natif ; c'est indispensable pour RDP. Pour SSH, coller 246 caractères à chaque connexion est inutilisable, et les contournements (`SSH_ASKPASS`) sont fragiles.

## Décision

### Parcours

1. **`ostena login`**, sur le poste de l'administrateur, s'authentifie auprès du core en HTTPS (mot de passe et TOTP ; certificat du core vérifié contre la racine épinglée). Il génère localement une paire ECDSA P-256 ; la clé privée ne quitte pas le poste. Le core renvoie un **certificat utilisateur OpenSSH** signé par sa CA SSH :
   - principal : l'identifiant de l'utilisateur ;
   - identifiant de clé : celui de la session de connexion ;
   - validité : celle de la session, 8 h au plus ;
   - aucune extension de redirection.

   `ostena login` écrit dans `~/.ostena/`, en droits privés : la clé, le certificat, un fragment `ssh_config` et une ligne `@cert-authority` pour l'hôte du bastion.
2. **`ssh root@srv-lab01@bastion`** joint le **serveur SSH natif de l'agent** (port 2222 par défaut). L'agent présente un certificat d'hôte signé par la CA d'hôte du core : le client le vérifie strictement, sans confiance au premier contact. L'utilisateur s'authentifie par clé publique avec son certificat ; l'agent vérifie la signature de la CA (clé poussée par le core), la validité et le principal.
3. **L'agent lit le nom d'utilisateur** et le coupe au **dernier `@`** : `root@srv-lab01` donne le compte `root` et la ressource `srv-lab01`. Un compte contenant un `@` (UPN : `admin@corp.local@srv-lab01`) reste entier. Il envoie au core, par le tunnel, une demande de grant : sujet, session de connexion, empreinte du certificat, compte, ressource, protocole, adresse du client.
4. **Le core** vérifie que la session de connexion est active, puis le droit, et **émet un grant** dont l'audience est le groupe de l'agent. Pour SSH, le grant est donc remis à l'agent et non à l'utilisateur ; il garde son rôle : une autorisation signée, à usage unique, auditée et vérifiée par le même code que pour les autres protocoles.
5. **L'agent ouvre la session** par le chemin commun (ADR-0008) : grant vérifié et jti consommé localement, `session_request`, jti consommé par le core, `session_params` (hôte, port, compte, empreinte de la clé hôte de la cible), contrôle de périmètre.
6. **Le driver client** joint la cible avec la clé de l'agent et vérifie strictement sa clé hôte, épinglée dans l'inventaire. Il relaie le terminal, écrit le transcript et le transmet au core.

**Révocation.** Une session `ostena login` dure 8 h et peut être révoquée sur le core. La révocation coupe aussi les sessions SSH en cours qui en dépendent, et elle est auditée.

### Clés de l'agent sur les cibles (jalon M1, avant le coffre-fort)

Chaque agent génère sa propre clé ECDSA P-256 ; la clé privée ne quitte jamais l'agent. Sa clé publique est déposée sur les cibles, restreinte :

```text
restrict,from="10.20.0.11,10.20.0.12" ecdsa-sha2-nistp256 AAAA… ostena-agent-gw01
```

- `from=` : les adresses des agents du groupe, telles que la cible les voit.
- `restrict` : coupe redirections de ports, d'agent et X11, et le terminal.
- Si une session interactive est autorisée sur la cible, ajouter `pty` après `restrict` (`restrict,pty,from=…`). Seulement dans ce cas.

**Dépôt** :
1. afficher la clé publique de l'agent sur l'agent : `ostena agent ssh-key --from 10.20.0.11,10.20.0.12` donne la ligne complète à déposer (`--pty` ajoute `pty`, `--line` n'imprime que la ligne ; sans `--from`, la ligne porte un repère `ADRESSES_DES_AGENTS` à remplacer) ;
2. la déposer dans `authorized_keys` du compte cible avec les options ci-dessus, par l'outil de gestion de configuration du client ;
3. vérifier depuis le bastion qu'une session aboutit, et que la même clé est refusée depuis une autre adresse.

**Rotation** :
1. générer la nouvelle clé sur l'agent : l'ancienne reste active ;
2. déposer la nouvelle clé publique **à côté** de l'ancienne, avec les mêmes options ;
3. basculer l'agent sur la nouvelle clé et vérifier une session ;
4. retirer l'ancienne ligne de toutes les cibles, puis supprimer l'ancienne clé de l'agent.

Rotation au moins annuelle, et immédiate si l'agent est compromis ou réinstallé. Le coffre-fort remplacera ce mécanisme par des secrets gérés.

### Algorithmes et pré-contrôle

**Liste figée**, non négociable par le client ni par la cible (écart et confinement : ADR-0009) :

| Mécanisme | Algorithme |
|---|---|
| Échange de clés | `ecdh-sha2-nistp256` seul |
| Chiffrement | `aes256-gcm@openssh.com` seul, donc pas de MAC séparé |
| Clés hôte et utilisateur, certificats | `ecdsa-sha2-nistp256` (et sa variante certificat) seul |
| Compression | aucune |
| Strict KEX | obligatoire (CVE-2023-48795) |

Une cible doit donc avoir une clé hôte ECDSA P-256. C'est le cas par défaut d'OpenSSH sous Debian.

**Pré-contrôle** (`ostena_ssh::precheck`), avant que la bibliothèque SSH lise le moindre octet du pair :

- **Lecture** : il lit en clair la ligne d'identification et le premier paquet, qui doit être un `KEXINIT`. Bornes : ligne de 255 octets CR LF compris, 16 lignes au plus avant l'identification (et seulement d'un serveur), paquet de 16 Kio au plus, délai de 10 s.
- **Refus** :
  - si le pair n'annonce pas le marqueur strict KEX de son rôle : `kex-strict-c-v00@openssh.com` d'un client, `kex-strict-s-v00@openssh.com` d'un serveur ;
  - si l'intersection avec la liste figée est vide pour l'échange de clés, la clé hôte, le chiffrement (chaque sens) ou la compression.
- **Rejeu** : l'identification valide passe tout de suite à la bibliothèque. Le paquet est retenu jusqu'à la décision, puis rejoué **tel quel**. Retenir aussi l'identification bloquerait deux extrémités pré-contrôlées l'une sur l'autre : chacune n'envoie son `KEXINIT` qu'après avoir lu l'identification de l'autre.
- **Audit** : chaque refus émet `ssh.precheck_refused`, avec le code, le rôle et le pair.

| Code | Signification |
|---|---|
| `SSH-E001` | ligne d'identification invalide (longueur, CR LF, version autre que 2.0, caractère non imprimable) |
| `SSH-E002` | premier paquet invalide (taille, bourrage, pas un `KEXINIT`, liste de noms invalide) |
| `SSH-E003` | identification et `KEXINIT` non reçus dans le délai |
| `SSH-E004` | pas de strict KEX |
| `SSH-E005` | aucun algorithme commun avec la liste figée (le type d'algorithme est précisé) |
| `SSH-E006` | connexion interrompue avant la négociation |
| `SSH-E007` | clé P-256 dont le scalaire est encodé sur moins de 32 octets (défaut amont, voir plus bas) |
| `SSH-E008` | clé privée SSH invalide (format, algorithme hors liste) |
| `SSH-E009` | génération de clé impossible |

L'analyseur est testé par propriétés et par une cible `cargo-fuzz` (`ssh_precheck`), dont le corpus part d'offres réelles capturées d'OpenSSH 9.5 (client) et 9.2 (serveur Debian 12).

Les deux extrémités s'annoncent `SSH-2.0-Ostena`, sans version : la valeur par défaut de la bibliothèque donnait son nom et sa version à tout pair.

### Certificats (`ostena_ssh::cert`)

**Un seul type** : `ecdsa-sha2-nistp256-cert-v01@openssh.com` (PROTOCOL.certkeys), signé par une autorité ECDSA P-256 en `ecdsa-sha2-nistp256`. Le codec est pur, borné et testé par une cible `cargo-fuzz` (`ssh_certificate`).

**Strict et canonique** : `encode(parse(b)) == b`. Sont refusés :
- un autre type de clé ou de courbe, une autorité ou une signature d'un autre algorithme ;
- un `mpint` non minimal ou négatif, un entier de signature nul ;
- des octets en trop, un champ réservé non vide ;
- des options critiques ou des extensions non triées ou répétées ;
- un certificat de plus de 4096 octets, plus de 16 principaux, un nonce hors de 16 à 64 octets, un texte avec un caractère de contrôle.

**Signature et vérification par `ostena-crypto`** (aws-lc) : émission en forme low-S avec un nonce de 32 octets tiré du système (`issue`) ; vérification stricte contre les autorités poussées (`verify`, qui rend le kid de l'autorité). `ssh-keygen` peut produire des signatures high-S, que la vérification stricte refuse : ses certificats ne servent qu'aux tests d'analyse. Les certificats émis par `issue` sont lus par `ssh-keygen -L`.

**Politique d'un certificat utilisateur** (`check_user`) :

| Règle | Valeur |
|---|---|
| Type | utilisateur |
| Principaux | un seul, l'UUID du sujet |
| Identifiant de clé | l'UUID de la session de connexion |
| Options critiques | aucune |
| Extensions | `permit-pty` seule ; toute redirection ou `permit-user-rc` refuse |
| Dates | début au plus 60 s dans le futur (défense en profondeur : la bibliothèque refuse avant), fin exclue, durée d'au plus 8 h 5 min |

Il en sort l'identité : sujet, session de connexion, terminal permis, SHA-256 du certificat.

**Certificat d'hôte de l'agent** (`check_host`) : type hôte, pour la clé d'hôte de l'agent, au moins un nom, aucune option ni extension, valide maintenant. Avant cela, `SshIdentity::new` vérifie sa signature contre les autorités d'hôtes poussées par le core (`host_ca_p256_public` de `ssh_trust`, ADR-0008) : un certificat d'une autre autorité, ou une confiance sans autorité d'hôtes, donne `SSH-E018`.

### Serveur SSH de l'agent (`ostena_ssh::server`)

**Uniquement par certificat.** Chaque connexion passe par le pré-contrôle. La configuration de la bibliothèque est reconstruite à chaque connexion depuis la dernière identité poussée (clé et certificat d'hôte, autorités d'utilisateurs ; `SSH-E018` si elle manque ou ne se vérifie pas), avec des bornes : fenêtre de 256 Kio, paquets de 32 Kio, 8 messages en attente par canal, 3 tentatives d'authentification.

**Authentification**, dans cet ordre ; la bibliothèque n'accepte qu'à la fin :
1. une clé nue est refusée (`SSH-E012`) ;
2. la bibliothèque vérifie les dates et la signature du certificat avec sa propre cryptographie, **mais ni l'autorité, ni le type, ni les principaux, ni les options, ni les extensions**. Le certificat est donc encodé de nouveau, analysé par le codec strict, vérifié contre les autorités poussées par `ostena-crypto`, puis soumis à la politique (`SSH-E011`) ;
3. le nom d'utilisateur est coupé au dernier `@` (`SSH-E010`) : compte de 1 à 256 octets, sans caractère de contrôle ni espace aux bords ; ressource `[a-z0-9][a-z0-9.-]{0,62}`. L'agent ne résout jamais la ressource : le core la traduit ;
4. l'autorisation (`Authorizer` ; en production, le chemin du tunnel de l'ADR-0008) décide (`SSH-E013`, avec le code sous-jacent : `GRT-E…`, `SCP-E…`, `TUN-E…` ou un code du core) ;
5. le driver se connecte à la cible aussitôt, pendant que le client ouvre son canal.

Un certificat refusé par la bibliothèque elle-même (expiré, pas encore valide, signature invalide) n'atteint pas ces contrôles ; il est tout de même audité à la fin de la connexion (`ssh.auth_refused`, `SSH-E011`).

La session est inscrite parmi les sessions vivantes **avant** que l'autorisation ne décide : une révocation de la session de connexion arrivée pendant la décision la coupe dès son ouverture. Tout accès accordé est clos **une et une seule fois** (`Authorizer::closed` et `ssh.session_closed`), quoi qui mette fin à la connexion, puisque le grant est consommé.

**Bornes** (`SSH-E019`, `ssh.connection_limited`) : connexions non authentifiées (16 par défaut, et 4 par adresse source), sessions authentifiées (64), autorisations en cours (32). Une connexion doit s'authentifier dans le délai `login_grace` (30 s).

**Un seul canal de session par connexion** (un second : `SSH-E017`). Sont relayés vers la cible, avec sa réponse :
- le terminal, seulement si le certificat porte `permit-pty`, borné (type de 64 caractères, 10 000 colonnes ou lignes) ;
- le shell, la commande (32 Kio au plus), les changements de taille, les signaux ;
- les variables d'environnement `LANG` et `LC_*`, seules.

Sont refusés explicitement, avec `ssh.channel_refused` (`SSH-E017`) : les sous-systèmes (dont `sftp`), la redirection de ports dans les deux sens (`tcpip-forward`, `direct-tcpip`), la redirection d'agent et X11.

**Une commande n'est journalisée que par sa longueur et son SHA-256** (`ssh.exec`), jamais en clair : une ligne de commande peut contenir un secret. Son texte relèvera des transcripts (crochet `SessionObserver`, vide pour l'instant).

**Relais** : une tâche par sens ; fin de données, code de sortie et signal sont rendus au client ; les octets relayés sont comptés et remis à `Authorizer::closed`. Une session prend fin à sa durée maximale (`ssh.session_expired`), à la révocation de sa session de connexion (`revoke_login`, `ssh.session_revoked`) ou à l'arrêt.


### Driver vers les cibles (`ostena_ssh::driver`)

- **Seule une `PinnedTarget` se joint** : ses adresses ont passé le contrôle de périmètre, aucune résolution de nom ici (anti-SSRF par le type). Elles sont essayées dans l'ordre.
- Pré-contrôle en client ; la clé d'hôte de la cible doit être **exactement** le point SEC1 épinglé dans l'inventaire (`SSH-E014`, `ssh.target_host_key_mismatch`) ; un certificat d'hôte de cible n'est pas accepté.
- Authentification par clé publique avec la clé de l'agent (`SSH-E015`, `ssh.target_auth_failed`).
- Tout dans le délai `target_connect_timeout` (5 s) ; cible injoignable ou négociation impossible : `SSH-E016`, `ssh.target_unreachable`.
- La bibliothèque accepte par défaut les canaux qu'un serveur ouvre vers son client : une cible ne doit jamais en ouvrir vers l'agent. Redirections, agent, X11, sessions, `direct-tcpip` et `streamlocal` ouverts par la cible sont refusés (`SSH-E017`, `ssh.target_channel_refused`).

### Configuration (`[agent.ssh]`)

| Clé | Défaut | Bornes |
|---|---|---|
| `listen` | requis | liste d'adresses `hôte:port` |
| `host_key`, `target_key`, `host_certificate` | `ssh_host_key`, `ssh_target_key`, `ssh_host_certificate` dans le dossier d'état (celui du journal anti-rejeu) | chemins absolus (`CFG-V008`) ; `host_key` et `target_key` distincts |
| `max_sessions` | 64 | 1 à 256 |
| `max_unauthenticated` | 16 | 1 à 256 |
| `max_unauthenticated_per_source` | 4 | 1 à 256 |
| `login_grace_secs` | 30 | 5 à 120 |
| `target_connect_timeout_secs` | 5 | 1 à 30 |

Une valeur hors bornes, une adresse invalide ou la même clé pour l'hôte et les cibles donnent `CFG-V015`. Une clé SSH lisible par un autre compte donne `CFG-P008`.

### Liaison dans l'agent (jalon M1, PR 6)

Quand `[agent.ssh]` est présent, `ostena agent run` démarre le serveur SSH à côté de la liaison au core :

- **Clés** : au premier démarrage, l'agent crée `host_key` et `target_key` par `ostena_ssh::keys` (scalaire de 32 octets tiré par `ostena-crypto`), avec des droits privés (0600 au compte du service, ACL protégée sous Windows), et journalise `agent.ssh_key_created`. L'écriture est atomique : fichier temporaire `<clé>.new` créé de façon exclusive avec les droits finaux (un reste d'écriture interrompue est d'abord supprimé, un lien comme un lien), écrit, synchronisé, puis renommé ; un arrêt pendant la création ne laisse jamais de clé tronquée. Une clé existante est relue et validée ; une clé illisible ou incohérente (`SSH-E008`), ou touchée par le défaut amont (`SSH-E007`), arrête le démarrage, avec un message qui dit quoi faire : supprimer le fichier et redémarrer, puis déposer la nouvelle clé sur les cibles (clé des cibles) ou laisser le core certifier la nouvelle clé d'hôte. `CFG-P008` les vérifie ensuite comme les autres fichiers secrets.
- **Clé d'hôte** : à chaque connexion au core, l'agent envoie sa clé publique d'hôte, liée à l'empreinte de son certificat mTLS (`AgentLink::subscribe_connected`, `agent.ssh_host_key_sent`). Le certificat d'hôte reçu dans `ssh_trust` est vérifié contre les autorités d'hôtes poussées avec lui (PR 5a), puis écrit dans `host_certificate` (remplacement atomique, comme les clés : fichier temporaire créé de façon exclusive, jamais à travers un lien), et l'identité SSH n'est prête qu'avec lui (`agent.ssh_identity_ready`, ou `agent.ssh_identity_refused` avec `SSH-E018`). Tant qu'elle n'est pas prête, le serveur refuse les connexions avant la bannière. La confiance est appliquée en entier ou pas du tout (fermé par défaut) : chaque push reconstruit l'identité avec ses autorités d'utilisateurs, et un push que l'agent ne peut pas appliquer (sans certificat d'hôte, certificat refusé, aucune autorité d'utilisateurs) **retire** l'identité précédente avec ses autorités (`agent.ssh_identity_refused`, `SSH-E018`, champ `withdrawn`). Les connexions déjà authentifiées continuent jusqu'à leur fin ou leur révocation.
- **Autorisation** : chaque accès passe par la passerelle du tunnel (grant, journal anti-rejeu partagé avec les autres sessions, `session_params`, contrôle de périmètre, driver avec `target_key` et la clé hôte épinglée). Sans liaison établie, l'accès est refusé (`TUN-E026`). La fin de session est rapportée au core (`SessionClosed`).
- **Révocations** : chaque `login_revoked` coupe les sessions de la session de connexion (`agent.login_revocation_applied`) ; le traitement est idempotent, une révocation reçue deux fois ne coupe rien de plus. Si le canal a débordé (`Lagged`), **toutes** les sessions SSH sont coupées (`ssh.revocations_lost`, `SSH-E020`, niveau avertissement).
- **Arrêt** : le serveur SSH et les autres sessions s'arrêtent ensemble, dans un seul délai de grâce (`agent.shutdown_grace_secs`) pour tous. Le serveur cesse d'écouter, déconnecte ses sessions et attend, dans ce délai, la fin des sessions, y compris celles dont l'autorisation est en cours, et l'envoi de leurs bilans `SessionClosed` au core ; le lien au core n'est fermé qu'ensuite (`agent.ssh_stopped`, avec `remaining` et `reports_unsent` si le délai est dépassé). Une adresse d'écoute inutilisable arrête le démarrage (`AGT-E010`).
- **État** : `ostena agent status` affiche les adresses d'écoute, le nombre de sessions SSH, l'état de l'identité, la fin de validité du certificat d'hôte, la version de confiance appliquée et la dernière reçue, et la raison d'un refus.
- **Fonctionnalité `ssh`** d'`ostena-cli`, active par défaut. Un binaire construit sans elle refuse de démarrer avec `[agent.ssh]` ; il sert de référence à la mesure d'empreinte, et `cargo xtask check-release` refuse un binaire de release qui ne l'a pas.

### Codes et événements de la session

| Code | Signification |
|---|---|
| `SSH-E010` | nom d'utilisateur invalide (pas de `@`, compte ou ressource invalide) |
| `SSH-E011` | certificat utilisateur refusé (format, autorité, signature, politique) |
| `SSH-E012` | clé publique nue refusée |
| `SSH-E013` | accès refusé ; l'événement porte le code sous-jacent (`cause`) |
| `SSH-E014` | clé d'hôte de la cible différente de celle épinglée |
| `SSH-E015` | la cible refuse la clé de l'agent |
| `SSH-E016` | cible injoignable ou délai dépassé |
| `SSH-E017` | canal ou requête refusé |
| `SSH-E018` | certificat d'hôte ou identité SSH de l'agent invalide |
| `SSH-E019` | limite du serveur atteinte |
| `SSH-E020` | révocations perdues (canal débordé) : toutes les sessions SSH coupées |

Événements (journal structuré, messages en français, textes du pair bornés et assainis : caractères de contrôle et de format Unicode, dont les contrôles bidirectionnels, remplacés ; aucun nom de champ masqué par la règle des journaux) : `ssh.connection_limited`, `ssh.connection_refused`, `ssh.auth_refused`, `ssh.access_refused`, `ssh.session_opened`, `ssh.exec`, `ssh.session_expired`, `ssh.session_revoked`, `ssh.session_closed` (raison, octets dans chaque sens, durée), `ssh.channel_refused` ; côté driver `ssh.target_host_key_mismatch`, `ssh.target_auth_failed`, `ssh.target_unreachable`, `ssh.target_channel_refused` ; côté tunnel `agent.ssh_trust_applied`, `agent.ssh_trust_refused`, `agent.login_revoked` (ADR-0008) ; côté agent `agent.ssh_started`, `agent.ssh_stopped`, `agent.ssh_unavailable`, `agent.ssh_key_created`, `agent.ssh_host_key_sent`, `agent.ssh_host_key_unsent`, `agent.ssh_identity_ready`, `agent.ssh_identity_refused`, `agent.login_revocation_applied`, `agent.session_report_lost`, `ssh.revocations_lost`. Les événements du serveur portent l'adresse du client (`peer`) et celle d'écoute (`listener`).

### Défaut amont : clés P-256 à scalaire court

`ssh-key 0.7.0-rc.11`, imposée par russh, refuse une clé privée P-256 dont OpenSSH encode le scalaire sur **31 octets ou moins** : `Encoding(Length)`. OpenSSH écrit le scalaire en `mpint` minimal. Il tombe à 31 octets quand son premier octet est nul et que le deuxième est inférieur à 0x80, soit environ **une clé sur 512** produite par `ssh-keygen`. Constaté sur 600 clés générées (une refusée), confirmé par décodage de la clé fautive et par un test qui fabrique une telle clé. OpenSSH l'accepte ; seul `ssh-key` la refuse. Les clés à 32 ou 33 octets passent.

- **Les clés de l'agent et celles d'`ostena login`** sont générées par `ostena-crypto` (aws-lc-rs), jamais par `ssh-key` ni par `rand` (`ostena_ssh::keys`). Le scalaire occupe 32 octets : un scalaire dont le premier octet est nul est tiré à nouveau, ce qui coûte moins de 0,006 bit sur 256. Imposer un `mpint` de 32 octets avec un zéro de tête superflu n'est pas possible : il ne serait pas canonique, et OpenSSH le refuse.
- **Une clé importée par un administrateur et touchée par le défaut** est refusée avec un message explicite (`SSH-E007` : « clé P-256 refusée : son scalaire privé est encodé sur 31 octets… générez-en une nouvelle, ou laissez Ostena générer la clé ») plutôt qu'une erreur de format.
- **Tests** : un test par propriétés vérifie que toute clé générée est relue par `ssh-key` et acceptée par OpenSSH (`ssh-keygen -y`). Un test documente le défaut (clé à 31 octets refusée par `ssh-key`, acceptée par OpenSSH) ; il échouera quand `ssh-key` sera corrigé, signal pour retirer le contournement.
- Les tests et les scripts qui passent par `ssh-keygen` régénèrent une clé que russh ne sait pas lire.
- À signaler en amont, et à revérifier avec `ssh-key` 0.7 stable : c'est l'un des critères de réexamen de l'ADR-0009.

### Limites et écarts connus (jalon M1, PR 4)

- ~~**Le grant ne signe ni le compte ni la session de connexion.**~~ **Levée à la PR 5a** : le grant v2 (ADR-0004) porte une liaison de 128 bits à la session de connexion et au compte, que l'agent recalcule et exige après avoir consommé le jti (`TUN-E010`, grant brûlé). Le contrôle du compte dans `session_params` reste.
- **`ssh.exec` journalise un SHA-256 simple** de la commande : pour une commande courte, il se retrouve par dictionnaire. La PR 8 le remplace par un hachage à clé (HMAC avec une clé d'audit, par `ostena-crypto`).
- **Requêtes relayées une à une** : la bibliothèque ne garde qu'un indicateur « réponse attendue » par canal, si bien que chaque requête (terminal, shell, commande, environnement) est transmise à la cible et sa réponse attendue dans le rappel, jusqu'à 10 s, en bloquant la boucle de la connexion. Une seule file de réponses par canal.
- **Adresses de la cible essayées l'une après l'autre** par le driver, dans le délai global de 5 s : une première adresse muette peut consommer tout le délai.
- **Flux couplés** : la bibliothèque traite une connexion dans une seule boucle ; un flux montant et un flux descendant tous deux massifs et couplés (une cible qui ne lit plus tant qu'elle ne peut écrire) peuvent se bloquer mutuellement au-delà des tampons. Le terminal et les commandes usuelles ne sont pas concernés ; à revoir avec les transferts de fichiers.
- **Aucune tolérance d'horloge sur le début de validité** : la bibliothèque refuse un certificat dont le début est encore à venir avant nos contrôles ; la marge de 60 s de `check_user` n'est qu'une défense en profondeur.
- ~~**Clé de la CA d'hôte**~~ : **levée à la PR 5a**. `ssh_trust` porte les autorités d'hôtes (`host_ca_p256_public`, 1 à 4) et l'agent vérifie la signature de son certificat d'hôte (`SSH-E018`).
- **Chemins par défaut des clés SSH** : confirmés à la PR 6, dans le dossier d'état (celui du journal anti-rejeu).
- **Révocations perdues par le consommateur** : levée à la PR 6 (`SSH-E020`, toutes les sessions coupées).

### Limites et écarts connus (jalon M1, PR 6)

- **Révocations perdues pendant une coupure du tunnel** : un `login_revoked` émis par le core pendant que la liaison est coupée n'arrive pas à l'agent, et les sessions SSH en cours continuent jusqu'à leur fin ou à la durée maximale du grant. Pas de coupure automatique au jalon M1 (décision du responsable du projet) : la PR 5b fera repousser par le core les révocations récentes à chaque reconnexion, ce que l'agent traite déjà de façon idempotente.
- **Adresses locales relevées au démarrage** : le contrôle de périmètre de l'agent prend un instantané de ses propres adresses au démarrage, sans le rafraîchir. Une adresse ajoutée ensuite n'est pas reconnue comme locale avant un redémarrage.
- **Test de bout en bout hors de l'hôte** : le plancher du périmètre refuse la boucle locale et les adresses de l'agent, et une politique poussée ne peut pas le lever. Le parcours complet du test `agent_ssh` (session, révocation, clé hôte de la cible inattendue) demande donc une cible sur une autre machine : un conteneur Debian 12 en CI (`tests/ssh/native-e2e.sh`), ou une cible donnée par les variables `OSTENA_E2E_*`. Sans elles, le test vérifie la mise en place et les refus (certificat expiré, ressource inconnue, cible en boucle locale).

## Conséquences

- **Interopérabilité vérifiée** :
  - client OpenSSH 9.x vers le serveur de l'agent : la session aboutit, et un client limité à des algorithmes hors liste est refusé ;
  - client de l'agent vers un sshd OpenSSH 9.2 de Debian 12 (`tests/ssh/debian12-target.sh`), avec une clé déposée en `restrict,from=` : la session aboutit, et une clé hôte inattendue est refusée ;
  - client OpenSSH (9.5 sous Windows, 9.2 sous Debian 12) avec un certificat, `@cert-authority` et `StrictHostKeyChecking=yes`, à travers le serveur de l'agent jusqu'à une cible (`tests/interop.rs`) : la session aboutit ; sont refusés une autorité d'hôte non reconnue, une clé nue, une autre autorité d'utilisateurs, un certificat expiré, `permit-port-forwarding`, un nom sans ressource, un refus de l'autorisation, `-W` (`direct-tcpip`, comme `-L`), `-R` et `-s sftp` ; la durée maximale et la révocation coupent la session ;
  - le parcours complet par le tunnel et le core de test (`tests/gateway.rs`) : jti consommé des deux côtés, rejeu refusé, sujet ou compte différents (`TUN-E010`), clé hôte absente, cibles de métadonnées ou de boucle locale refusées par le périmètre, rien sans confiance poussée (`TUN-E026`) ;
  - de bout en bout (`tests/ssh/native-e2e.sh`, test `agent_ssh` d'`ostena-cli`) : client OpenSSH, binaire `ostena agent run` réel avec `[agent.ssh]`, tunnel, core de test, driver, sshd Debian 12 avec la clé de l'agent en `restrict,from=` ; la révocation coupe la session et une clé hôte de cible inattendue est refusée (`SSH-E014`).
- **Latence ajoutée** mesurée par `cargo bench -p ostena-ssh --bench relay` (aller-retour de 64 octets dans un shell, à travers le serveur et le driver, comparé au même aller-retour direct vers la cible, en boucle locale) : **120 µs au p99 sous Windows 11** et **52 µs au p99 sous Linux** (conteneur Docker, WSL2), pour un objectif de 3 ms. Établissement d'une session complète (contrôles du certificat, autorisation, connexion à la cible, canal, shell) : 5,6 ms au p50 sous Windows, 5,1 ms sous Linux, pour un objectif de 5 s. Les sockets du serveur et du driver sont en `TCP_NODELAY` : sans cela, Nagle et les accusés de réception différés ajoutaient environ 100 ms à l'établissement sous Linux. Affiché en CI sans seuil bloquant (ADR-0005).
- **Clients exclus** : un client trop ancien pour le strict KEX ou pour AES-GCM est refusé. C'est voulu.
- **Le grant n'apparaît pas** dans le parcours SSH de l'utilisateur. Pour RDP, il reste remis à l'utilisateur (ADR-0004).
