# ADR-0010 : Accès SSH natif

- **Statut** : Accepté en partie. Le parcours, les clés de l'agent sur les cibles, la liste d'algorithmes et le pré-contrôle sont décidés. Ce dernier est implémenté avec la configuration de la bibliothèque (jalon M1, PR 1). Les certificats, le serveur SSH de l'agent et le driver vers les cibles sont implémentés comme bibliothèque, avec leurs messages de tunnel (jalon M1, PR 4). L'autorisation par le core (session de connexion, droit, émission du grant et des certificats) vient à la PR 5, la liaison dans l'agent à la PR 6, les transcripts ensuite.
- **Date** : 2026-11-13
- **Révision** : 2026-11-15, certificats, serveur, driver, codes `SSH-E010` à `SSH-E019`, événements (jalon M1, PR 4)

## Contexte

L'administrateur doit joindre une cible avec son client SSH habituel, sans plugin : `ssh root@srv-lab01@bastion`. Le bastion doit l'authentifier fortement, vérifier son droit et tracer la session, sans que l'agent passerelle détienne de base de données ni de secret partagé.

Le format des grants (ADR-0004) prévoit qu'un grant puisse transiter dans un champ de mot de passe d'un client natif ; c'est indispensable pour RDP. Pour SSH, coller 224 caractères à chaque connexion est inutilisable, et les contournements (`SSH_ASKPASS`) sont fragiles.

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
1. afficher la clé publique de l'agent sur l'agent (`ostena agent ssh-key`, à venir) ;
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
| Dates | début au plus 60 s dans le futur, fin exclue, durée d'au plus 8 h 5 min |

Il en sort l'identité : sujet, session de connexion, terminal permis, SHA-256 du certificat.

**Certificat d'hôte de l'agent** (`check_host`) : type hôte, pour la clé d'hôte de l'agent, au moins un nom, aucune option ni extension, valide maintenant.

### Serveur SSH de l'agent (`ostena_ssh::server`)

**Uniquement par certificat.** Chaque connexion passe par le pré-contrôle. La configuration de la bibliothèque est reconstruite à chaque connexion depuis la dernière identité poussée (clé et certificat d'hôte, autorités d'utilisateurs ; `SSH-E018` si elle manque ou ne se vérifie pas), avec des bornes : fenêtre de 256 Kio, paquets de 32 Kio, 8 messages en attente par canal, 3 tentatives d'authentification.

**Authentification**, dans cet ordre ; la bibliothèque n'accepte qu'à la fin :
1. une clé nue est refusée (`SSH-E012`) ;
2. la bibliothèque vérifie les dates et la signature du certificat avec sa propre cryptographie, **mais ni l'autorité, ni le type, ni les principaux, ni les options, ni les extensions**. Le certificat est donc encodé de nouveau, analysé par le codec strict, vérifié contre les autorités poussées par `ostena-crypto`, puis soumis à la politique (`SSH-E011`) ;
3. le nom d'utilisateur est coupé au dernier `@` (`SSH-E010`) : compte de 1 à 256 octets, sans caractère de contrôle ni espace aux bords ; ressource `[a-z0-9][a-z0-9.-]{0,62}`. L'agent ne résout jamais la ressource : le core la traduit ;
4. l'autorisation (`Authorizer` ; en production, le chemin du tunnel de l'ADR-0008) décide (`SSH-E013`, avec le code sous-jacent : `GRT-E…`, `SCP-E…`, `TUN-E…` ou un code du core) ;
5. le driver se connecte à la cible aussitôt, pendant que le client ouvre son canal.

Un certificat refusé par la bibliothèque elle-même (expiré, pas encore valide, signature invalide) n'atteint pas ces contrôles ; il est tout de même audité à la fin de la connexion (`ssh.auth_refused`, `SSH-E011`).

**Bornes** (`SSH-E019`, `ssh.connection_limited`) : connexions non authentifiées (16 par défaut), sessions authentifiées (64), autorisations en cours (32). Une connexion doit s'authentifier dans le délai `login_grace` (30 s).

**Un seul canal de session par connexion** (un second : `SSH-E017`). Sont relayés vers la cible, avec sa réponse :
- le terminal, seulement si le certificat porte `permit-pty`, borné (type de 64 caractères, 10 000 colonnes ou lignes) ;
- le shell, la commande (32 Kio au plus), les changements de taille, les signaux ;
- les variables d'environnement `LANG` et `LC_*`, seules.

Sont refusés explicitement, avec `ssh.channel_refused` (`SSH-E017`) : les sous-systèmes (dont `sftp`), la redirection de ports dans les deux sens (`tcpip-forward`, `direct-tcpip`), la redirection d'agent et X11.

**Une commande n'est journalisée que par sa longueur et son SHA-256** (`ssh.exec`), jamais en clair : une ligne de commande peut contenir un secret. Son texte relèvera des transcripts (crochet `SessionObserver`, vide pour l'instant).

**Relais** : une tâche par sens ; fin de données, code de sortie et signal sont rendus au client ; les octets relayés sont comptés et remis à `Authorizer::closed`. Une session prend fin à sa durée maximale (`ssh.session_expired`), à la révocation de sa session de connexion (`revoke_login`, `ssh.session_revoked`) ou à l'arrêt.

**Limite connue** : la bibliothèque traite une connexion dans une seule boucle ; un flux montant et un flux descendant tous deux massifs et couplés (une cible qui ne lit plus tant qu'elle ne peut écrire) peuvent se bloquer mutuellement au-delà des tampons. Le terminal et les commandes usuelles ne sont pas concernés ; à revoir avec les transferts de fichiers.

### Driver vers les cibles (`ostena_ssh::driver`)

- **Seule une `PinnedTarget` se joint** : ses adresses ont passé le contrôle de périmètre, aucune résolution de nom ici (anti-SSRF par le type). Elles sont essayées dans l'ordre.
- Pré-contrôle en client ; la clé d'hôte de la cible doit être **exactement** le point SEC1 épinglé dans l'inventaire (`SSH-E014`, `ssh.target_host_key_mismatch`) ; un certificat d'hôte de cible n'est pas accepté.
- Authentification par clé publique avec la clé de l'agent (`SSH-E015`, `ssh.target_auth_failed`).
- Tout dans le délai `target_connect_timeout` (5 s) ; cible injoignable ou négociation impossible : `SSH-E016`, `ssh.target_unreachable`.

### Configuration (`[agent.ssh]`, lue et validée dès maintenant, utilisée à la PR 6)

| Clé | Défaut | Bornes |
|---|---|---|
| `listen` | requis | liste d'adresses `hôte:port` |
| `host_key`, `target_key`, `host_certificate` | `ssh_host_key`, `ssh_target_key`, `ssh_host_certificate` dans le dossier d'état (celui du journal anti-rejeu) | chemins absolus (`CFG-V008`) ; `host_key` et `target_key` distincts |
| `max_sessions` | 64 | 1 à 256 |
| `max_unauthenticated` | 16 | 1 à 256 |
| `login_grace_secs` | 30 | 5 à 120 |
| `target_connect_timeout_secs` | 5 | 1 à 30 |

Une valeur hors bornes, une adresse invalide ou la même clé pour l'hôte et les cibles donnent `CFG-V015`. Une clé SSH lisible par un autre compte donne `CFG-P008`, dès que l'agent l'a créée.

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

Événements (journal structuré, messages en français, textes du pair bornés et assainis, aucun nom de champ masqué par la règle des journaux) : `ssh.connection_limited`, `ssh.connection_refused`, `ssh.auth_refused`, `ssh.access_refused`, `ssh.session_opened`, `ssh.exec`, `ssh.session_expired`, `ssh.session_revoked`, `ssh.session_closed` (raison, octets dans chaque sens, durée), `ssh.channel_refused` ; côté driver `ssh.target_host_key_mismatch`, `ssh.target_auth_failed`, `ssh.target_unreachable` ; côté tunnel `agent.ssh_trust_applied`, `agent.ssh_trust_refused`, `agent.login_revoked` (ADR-0008). Les événements du serveur portent l'adresse du client (`peer`) et celle d'écoute (`listener`).

### Défaut amont : clés P-256 à scalaire court

`ssh-key 0.7.0-rc.11`, imposée par russh, refuse une clé privée P-256 dont OpenSSH encode le scalaire sur **31 octets ou moins** : `Encoding(Length)`. OpenSSH écrit le scalaire en `mpint` minimal. Il tombe à 31 octets quand son premier octet est nul et que le deuxième est inférieur à 0x80, soit environ **une clé sur 512** produite par `ssh-keygen`. Constaté sur 600 clés générées (une refusée), confirmé par décodage de la clé fautive et par un test qui fabrique une telle clé. OpenSSH l'accepte ; seul `ssh-key` la refuse. Les clés à 32 ou 33 octets passent.

- **Les clés de l'agent et celles d'`ostena login`** sont générées par `ostena-crypto` (aws-lc-rs), jamais par `ssh-key` ni par `rand` (`ostena_ssh::keys`). Le scalaire occupe 32 octets : un scalaire dont le premier octet est nul est tiré à nouveau, ce qui coûte moins de 0,006 bit sur 256. Imposer un `mpint` de 32 octets avec un zéro de tête superflu n'est pas possible : il ne serait pas canonique, et OpenSSH le refuse.
- **Une clé importée par un administrateur et touchée par le défaut** est refusée avec un message explicite (`SSH-E007` : « clé P-256 refusée : son scalaire privé est encodé sur 31 octets… générez-en une nouvelle, ou laissez Ostena générer la clé ») plutôt qu'une erreur de format.
- **Tests** : un test par propriétés vérifie que toute clé générée est relue par `ssh-key` et acceptée par OpenSSH (`ssh-keygen -y`). Un test documente le défaut (clé à 31 octets refusée par `ssh-key`, acceptée par OpenSSH) ; il échouera quand `ssh-key` sera corrigé, signal pour retirer le contournement.
- Les tests et les scripts qui passent par `ssh-keygen` régénèrent une clé que russh ne sait pas lire.
- À signaler en amont, et à revérifier avec `ssh-key` 0.7 stable : c'est l'un des critères de réexamen de l'ADR-0009.

## Conséquences

- **Interopérabilité vérifiée** :
  - client OpenSSH 9.x vers le serveur de l'agent : la session aboutit, et un client limité à des algorithmes hors liste est refusé ;
  - client de l'agent vers un sshd OpenSSH 9.2 de Debian 12 (`tests/ssh/debian12-target.sh`), avec une clé déposée en `restrict,from=` : la session aboutit, et une clé hôte inattendue est refusée ;
  - client OpenSSH (9.5 sous Windows, 9.2 sous Debian 12) avec un certificat, `@cert-authority` et `StrictHostKeyChecking=yes`, à travers le serveur de l'agent jusqu'à une cible (`tests/interop.rs`) : la session aboutit ; sont refusés une autorité d'hôte non reconnue, une clé nue, une autre autorité d'utilisateurs, un certificat expiré, `permit-port-forwarding`, un nom sans ressource, un refus de l'autorisation, `-W` (`direct-tcpip`, comme `-L`), `-R` et `-s sftp` ; la durée maximale et la révocation coupent la session ;
  - le parcours complet par le tunnel et le core de test (`tests/gateway.rs`) : jti consommé des deux côtés, rejeu refusé, sujet ou compte différents (`TUN-E010`), clé hôte absente, cibles de métadonnées ou de boucle locale refusées par le périmètre, rien sans confiance poussée (`TUN-E026`) ;
  - de bout en bout (`tests/ssh/native-e2e.sh`) : client OpenSSH, serveur de l'agent, tunnel, core de test, driver, sshd Debian 12 avec la clé de l'agent en `restrict,from=`.
- **Latence ajoutée** mesurée par `cargo bench -p ostena-ssh --bench relay` (aller-retour de 64 octets dans un shell, à travers le serveur et le driver, comparé au même aller-retour direct vers la cible, en boucle locale) : **120 µs au p99 sous Windows 11** et **52 µs au p99 sous Linux** (conteneur Docker, WSL2), pour un objectif de 3 ms. Établissement d'une session complète (contrôles du certificat, autorisation, connexion à la cible, canal, shell) : 5,6 ms au p50 sous Windows, 5,1 ms sous Linux, pour un objectif de 5 s. Les sockets du serveur et du driver sont en `TCP_NODELAY` : sans cela, Nagle et les accusés de réception différés ajoutaient environ 100 ms à l'établissement sous Linux. Affiché en CI sans seuil bloquant (ADR-0005).
- **Clients exclus** : un client trop ancien pour le strict KEX ou pour AES-GCM est refusé. C'est voulu.
- **Le grant n'apparaît pas** dans le parcours SSH de l'utilisateur. Pour RDP, il reste remis à l'utilisateur (ADR-0004).
