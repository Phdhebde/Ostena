# ADR-0010 : Accès SSH natif

- **Statut** : Accepté en partie. Le parcours, les clés de l'agent sur les cibles, la liste d'algorithmes et le pré-contrôle sont décidés. Ce dernier est implémenté avec la configuration de la bibliothèque (jalon M1, PR 1). Les certificats, le serveur SSH de l'agent et le driver vers les cibles sont implémentés comme bibliothèque, avec leurs messages de tunnel (jalon M1, PR 4). Le grant signe le compte et la session de connexion, et l'agent vérifie la signature de son certificat d'hôte (jalon M1, PR 5a). L'autorisation par le core (session de connexion, droit, émission du grant et du certificat d'hôte) est implémentée à la PR 5b (ADR-0014). Le serveur est lié dans l'agent, avec ses clés créées au premier démarrage et `ostena agent ssh-key` (jalon M1, PR 6). `ostena login` et `ostena logout`, avec l'émission des certificats utilisateur, sont implémentés à la PR 7 (ADR-0015). Le transcript de chaque session est transmis au core, et la session est coupée s'il ne peut plus l'être (jalon M1, PR 8, ADR-0016). Les transferts de fichiers (`scp`, `sftp`, `rsync`) et la redirection locale (`-L`, `-W`, `ProxyJump`) sont relayés sous les fonctions du droit, les autres demandes refusées et journalisées, et les algorithmes réellement offerts sont vérifiés en CI (jalon M2, PR 4a). `ostena config ssh` écrit les alias `Host` des accès de l'utilisateur (jalon M2, PR 4b). La redirection distante (`-R`), la redirection d'agent et X11 sont relayées sous leur fonction, les canaux ouverts par la cible n'étant acceptés que pour ce que l'utilisateur a demandé (jalon M2, PR 4c).
- **Date** : 2026-11-13
- **Révision** : 2026-11-15, certificats, serveur, driver, codes `SSH-E010` à `SSH-E019`, événements (jalon M1, PR 4)
- **Révision** : 2026-11-25, compte et session de connexion signés par le grant (format v2), autorités d'hôtes poussées et signature du certificat d'hôte vérifiée (jalon M1, PR 5a)
- **Révision** : 2026-11-25, liaison dans l'agent, clés créées par l'agent, `ostena agent ssh-key`, code `SSH-E020`, événements `agent.ssh_*` (jalon M1, PR 6)
- **Révision** : 2026-11-25, relecture de sécurité de la PR 6 : confiance fermée par défaut (identité retirée sur un push inapplicable), identité réévaluée aux dates du certificat d'hôte, arrêt dans un seul délai de grâce avec les bilans envoyés avant la fermeture du lien, clés et certificat d'hôte écrits de façon atomique, dossier des clés vérifié avant leur création
- **Révision** : 2026-11-25, `ostena login` et `ostena logout` : fichiers, API, codes `AUTH-E001` à `AUTH-E006` et `LOGIN-E001` à `LOGIN-E006`, événements (jalon M1, PR 7)
- **Révision** : 2026-11-25, transcripts (ADR-0016) : `ssh.exec` ne porte plus que la longueur, l'empreinte à clé est consignée par le core (`access.ssh_exec`) ; session coupée quand le transcript est perdu, y compris à la coupure du tunnel et au redémarrage du core (`SSH-E021`, `ssh.transcript_lost`) ; crochet `SessionObserver` retiré (jalon M1, PR 8)
- **Révision** : 2026-11-26, sessions tenues par le gestionnaire de sessions de l'agent (ADR-0018) : quotas par utilisateur et par ressource, identifiant de session unique, délai d'inactivité, `ssh.session_idle` (jalon M2, PR 1)
- **Révision** : 2026-11-26, `ostena config ssh` : alias `Host` des accès de l'utilisateur, liste signée par la clé de la session (`POST /v1/ssh-hosts`) (jalon M2, PR 4b)
- **Révision** : 2026-11-26, fonctions du droit (transfert, redirection de ports, d'agent, X11) portées par le grant ; transferts et `direct-tcpip` relayés sous leur fonction, noms de fichiers dans le transcript ; refus journalisés (`SSH-E022`, `ssh.request_refused`) ; flux SFTP illisible (`SSH-E023`) ; vérification des algorithmes offerts (jalon M2, PR 4a)
- **Révision** : 2026-11-26, relais de la redirection distante, de l'agent et de X11 : demande transmise à la cible (`ssh.forward_requested`), canaux ouverts par la cible acceptés seulement pour ce qu'elle a accordé, notés avant d'être relayés (jalon M2, PR 4c)

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

### `ostena login` et `ostena logout` (jalon M1, PR 7)

Le transport est décrit par l'ADR-0015, les mots de passe et le TOTP par l'ADR-0009 (amendement du 2026-11-25).

**Échange.** `POST /v1/login` porte le nom, le mot de passe, le code TOTP, la clé publique P-256 (point non compressé, base64url) et une durée facultative. La réponse porte la session de connexion, l'identifiant de l'utilisateur, le certificat, ses dates, la ligne de la CA d'hôte, les motifs d'hôtes du bastion et leur port. Les messages sont des types stricts (`ostena_common::api::login`) : champs inconnus refusés, 16 Kio au plus, cible `cargo-fuzz` `login_messages`. Aucune preuve de possession de la clé n'est demandée : le certificat ne sert qu'à qui détient la clé privée.

**Contrôles du client avant d'écrire.** Le certificat reçu doit certifier la clé envoyée, porter une signature valide de son autorité, passer `check_user`, et nommer l'utilisateur, la session et les dates de la réponse. Sinon rien n'est écrit (`LOGIN-E003`).

**Fichiers de `~/.ostena/`.** Le dossier est créé en 0700 ; chaque fichier est privé dès sa création (0600 sous Unix ; sous Windows, descripteur protégé : SYSTEM, les administrateurs et le compte courant) et remplacé atomiquement :

| Fichier | Contenu |
|---|---|
| `config.toml` | adresse du core et nom d'utilisateur, repris aux connexions suivantes |
| `root.pem` | racine épinglée ; une autre racine est refusée sans `--replace-root` (`LOGIN-E005`) |
| `id_ecdsa`, `id_ecdsa.pub` | clé de la session, nouvelle à chaque connexion, générée par `ostena-crypto` |
| `id_ecdsa-cert.pub` | certificat de la session |
| `known_hosts` | `@cert-authority [hôte]:port,… <clé de la CA d'hôte> ostena-host-ca` |
| `ssh_config` | fragment : `IdentityFile` (OpenSSH y associe `id_ecdsa-cert.pub` ; un `CertificateFile` explicite serait offert sans sa clé, que `PubkeyAcceptedAlgorithms` écarte), `IdentitiesOnly yes`, `IdentityAgent none`, `UserKnownHostsFile`, `StrictHostKeyChecking yes`, algorithmes de la liste, aucune redirection |

`ostena login` affiche la ligne `Include` à placer une fois en tête de `~/.ssh/config` ; `--install-include` l'y ajoute, une seule fois, et refuse un `~/.ssh/config` qui est un lien symbolique (il le remplacerait par un fichier). Les chemins écrits entre guillemets dans `ssh_config` refusent un guillemet, un caractère de contrôle, un chemin non UTF-8 et une barre oblique inverse qu'OpenSSH lirait comme un échappement (devant `\`, `'`, `"`, ou en dernier) ; la barre oblique inverse simple des chemins Windows reste valide. Un motif de `ssh_hosts` fait seulement de jokers et de points (`*`, `*.*`) est refusé, dans la configuration (`CFG-V017`) comme dans la réponse du core. OpenSSH lit les fichiers tels qu'écrits (test `openssh_reads_the_files` : `ssh-keygen -L`, `ssh-keygen -y`, `ssh -G`).

**Déconnexion.** `ostena logout` envoie `POST /v1/logout` avec la session, le certificat, l'heure et une signature ECDSA de la clé de la session sur `"ostena-logout-v1\0" ‖ session ‖ heure`. L'heure est acceptée à ±60 s de celle du core (`LOGOUT_SKEW_SECS`). Le core révoque la session, puis le client supprime la clé et le certificat (et les alias d'`ostena config ssh`). La réponse est `204`.

**Alias (`ostena config ssh`, jalon M2, PR 4b).** Pour taper `ssh srv-lab01` au lieu de `ssh root@srv-lab01@bastion`, `ostena config ssh` demande au core les accès que l'utilisateur détient maintenant : `POST /v1/ssh-hosts`, avec les mêmes champs qu'un logout, signés par la clé de la session sous un autre domaine (`"ostena-ssh-hosts-v1\0" ‖ session ‖ heure`, ±60 s) ; une signature de logout ne vaut pas pour une liste, ni l'inverse. Le core vérifie le certificat contre l'autorité utilisateur, la session (non révoquée, non expirée, de ce certificat) et l'utilisateur (actif), puis lit sans rien écrire les droits SSH valides, non révoqués, sur un compte et une ressource actifs. La réponse (`SshHostsResponse`, 256 Kio et 512 accès au plus, triés, chaque couple ressource et compte une fois, avec la fin du droit le plus long) donne, pour chaque accès, la ressource, le compte et le **nom d'hôte du bastion** : le premier nom d'hôte SSH du groupe de la ressource, sans joker, couvert par un motif de `[core.login] ssh_hosts`, puisque la ligne `@cert-authority` d'`ostena login` ne fait confiance qu'à ces motifs. Une ressource dont le groupe n'a pas de tel nom est omise (`login.ssh_hosts_listed`, champ `omitted`). Le client écrit `~/.ostena/ssh_hosts` (0600), que le fragment `ssh_config` inclut en tête : un bloc `Host <compte>.<ressource>` par accès, et `<ressource>` aussi quand c'est le seul compte de la ressource, avec `HostName`, `User compte@ressource` et les mêmes options que le fragment (clé, `known_hosts`, algorithmes figés, aucune redirection par défaut) : OpenSSH applique un bloc selon le nom tapé, pas selon le `HostName` atteint. Un compte qui contient autre chose que `[A-Za-z0-9._-]` n'est pas écrit : `ssh_config` le lirait comme un séparateur, un commentaire ou un jeton `%` ; la commande le signale. Les alias suivent les droits au moment de l'appel : un droit accordé ou révoqué ensuite demande de relancer la commande, et un alias resté en place ne donne aucun accès (le core décide à chaque session). Refus : `AUTH-E001`, comme un logout refusé (`login.ssh_hosts_refused` au journal).

**Saisie.** Le mot de passe est lu sans écho sur le terminal (`ostena_platform::tty`) ; le terminal est restauré même sur erreur ou Ctrl-C (Ctrl-C annule la saisie), immédiatement (`TCSANOW`). Sous Unix, un `SIGHUP`, `SIGTERM`, `SIGINT` ou `SIGQUIT` reçu pendant la saisie est intercepté : la saisie s'arrête, le terminal est restauré, puis le signal est relancé avec l'action précédente, qui termine le processus comme il l'aurait fait.

**Codes du core** (corps `{"protocol":1,"code":…,"message":…}`) :

| Code | HTTP | Signification |
|---|---|---|
| `AUTH-E001` | 401 | identifiants invalides ou compte indisponible : nom inconnu, mot de passe ou code faux, code rejoué, compte verrouillé, désactivé ou non enrôlé. Un seul message, quelle que soit la cause, et un seul délai : la réponse ne part pas avant 1 s après l'arrivée de la requête (plancher fixe, au-dessus du coût de PBKDF2, de la transaction et de l'écriture d'audit), ce qui égalise les temps mieux qu'un COMMIT factice ; vaut aussi pour un logout refusé |
| `AUTH-E002` | 429 | trop de tentatives depuis cette adresse |
| `AUTH-E003` | 400, 404, 405, 413, 415 | requête mal formée (route, méthode, type, taille, JSON, champ) |
| `AUTH-E004` | 400 | clé publique refusée |
| `AUTH-E005` | 400 | version du protocole non prise en charge |
| `AUTH-E006` | 503 | le core ne peut pas décider (base indisponible) |

**Codes du client** :

| Code | Signification |
|---|---|
| `LOGIN-E001` | core injoignable, ou poignée de main TLS refusée (certificat du core non signé par la racine épinglée pour ce nom) |
| `LOGIN-E002` | réponse du core invalide |
| `LOGIN-E003` | certificat reçu invalide ou différent de la demande |
| `LOGIN-E004` | fichier de `~/.ostena` illisible ou impossible à écrire |
| `LOGIN-E005` | racine différente de celle épinglée |
| `LOGIN-E006` | réglage manquant, saisie interrompue |

**Événements de l'écouteur** : `login.listener_started`, `login.connection_limited`, `login.tls_refused`, `login.exchange_timeout`, `login.rate_limited`, `login.accept_failed`.

**Événements de l'authentification** (avec l'authentificateur PostgreSQL) : `login.succeeded` (utilisateur, session, empreinte du certificat, fin de validité, adresse), `login.refused` (nom tel que saisi, assaini et borné, cause interne, adresse ; protecteur, dans la transaction, pour un compte connu, au mieux pour un nom inconnu), `login.locked` (fin du verrouillage) ; `ostena config ssh` n'écrit rien dans la chaîne (lecture seule ; `login.ssh_hosts_listed` et `login.ssh_hosts_refused` au journal) ; `ostena logout` écrit `login_session.revoked` avec l'utilisateur pour acteur, et les agents concernés sont prévenus comme pour une révocation par l'administrateur. Côté administration : `user.password_set`, `user.totp_enrolled`, `user.totp_reset`, `user.unlocked`. La cause précise d'un refus n'est que dans l'audit, jamais dans la réponse.

**Décision du core** (`ostena_core::authn`), en deux temps, pour ne tenir ni verrou de ligne ni place de calcul pendant qu'une autre tentative attend :
1. l'empreinte du mot de passe est lue sans verrou, puis PBKDF2 tourne hors des fils du runtime et hors de toute transaction ; la place de calcul (quatre à la fois) n'est tenue que pendant la dérivation. Un nom inconnu ou un compte sans empreinte reçoit une dérivation factice du même coût ;
2. une transaction verrouille ensuite, dans l'ordre canonique de l'ADR-0014, la ligne `app_user` (`FOR SHARE` : une désactivation concurrente attend l'ouverture de la session et la révoque, ou bien elle est vue) puis la ligne d'identifiants (`FOR UPDATE`). Elle revérifie que le compte est actif, non verrouillé, enrôlé (mot de passe, TOTP confirmé) et que son empreinte est celle qui a été dérivée ; sinon refus, sans compter d'échec. Le code TOTP est vérifié dans la transaction (un pas de tolérance, un pas jamais accepté deux fois). Un secret TOTP que la clé ne peut pas ouvrir (autre clé, ligne altérée) est un refus `AUTH-E001` compté comme un échec, avec le journal d'erreur `login.credential_invalid`, jamais une réponse 503 qui distinguerait ce compte ;
3. un échec compte ; à `max_failures` échecs consécutifs, le compte est verrouillé `lockout_minutes`. Les échecs décroissent : un échec ne s'ajoute aux précédents que s'il survient moins de `lockout_minutes` après le dernier (`last_failure_at`), sinon le compte repart à un ;
4. succès : compteurs remis à zéro, pas retenu, empreinte recalculée si ses paramètres ne sont plus ceux du binaire, certificat émis et session ouverte dans la même transaction que `login.succeeded`.

Le certificat commence 60 s avant l'heure du core (horloges) et finit avec la session : sa validité dépasse donc la session d'une minute, dans la limite de 8 h 5 min de `check_user`.

**Administration** : `ostena core user set-password`, `totp-enroll` puis `totp-enroll --confirm`, `totp-reset`, `unlock` ; `user list` montre l'état des identifiants ([exploitation](../exploitation/core-installation.md)).

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

La session réserve sa place dans le gestionnaire de sessions de l'agent (ADR-0018) **avant** que l'autorisation ne décide : une révocation de la session de connexion arrivée pendant la décision la coupe dès son ouverture. L'identifiant de session donné par le core doit être unique sur l'agent (`SSH-E013`, cause `SES-E004`). Tout accès accordé est clos **une et une seule fois** (`Authorizer::closed` et `ssh.session_closed`), quoi qui mette fin à la connexion, puisque le grant est consommé.

**Bornes** (`SSH-E019`, `ssh.connection_limited`) : connexions non authentifiées (16 par défaut, et 4 par adresse source), autorisations en cours (32), et les quotas du gestionnaire de sessions (ADR-0018) : sessions de l'agent (64), d'un utilisateur et vers une ressource (sans borne propre par défaut) ; l'événement porte alors la cause (`SES-E001` à `SES-E003`). Une connexion doit s'authentifier dans le délai `login_grace` (30 s).

**Un seul canal de session par connexion** (un second : `SSH-E017`). Sont relayés vers la cible, avec sa réponse :
- le terminal, seulement si le certificat porte `permit-pty`, borné (type de 64 caractères, 10 000 colonnes ou lignes) ;
- le shell, la commande (32 Kio au plus), les changements de taille, les signaux ;
- les variables d'environnement `LANG` et `LC_*`, seules.

Les transferts de fichiers et les redirections dépendent des **fonctions du droit** (section suivante) ; sans elles, ils sont refusés. Les autres sous-systèmes et `streamlocal-forward` sont refusés dans tous les cas (`ssh.channel_refused`, `SSH-E017`).

**Une commande n'est journalisée par l'agent que par sa longueur** (`ssh.exec`), jamais en clair : une ligne de commande peut contenir un secret. Son texte va dans le transcript, et le core en consigne une empreinte à clé (HMAC-SHA-256, `access.ssh_exec`, ADR-0016).

**Transcript, échec fermé** (ADR-0016) : à l'ouverture du shell ou de la commande, le serveur démarre le transcript sur le flux `Recording` ouvert avec la session (ADR-0008). Chaque sortie de la cible est remise à l'enregistreur **avant** d'être relayée à l'utilisateur ; les changements de taille de la fenêtre aussi. Si le transcript ne peut plus être transmis (flux refusé ou arrêté par le core, tunnel coupé, core redémarré), la session est coupée : `SSH-E021`, `ssh.transcript_lost`. La raison de fin (fermeture, révocation, expiration, arrêt, perte) est écrite dans la trame de fin.

**Relais** : une tâche par sens ; fin de données, code de sortie et signal sont rendus au client ; les octets relayés sont comptés et remis à `Authorizer::closed`. Une session prend fin à sa durée maximale (`ssh.session_expired`), à son délai d'inactivité s'il est configuré (`ssh.session_idle`, raison `inactive`, trame de fin `expired` : le format du transcript n'a pas de raison propre ; seules les données de l'utilisateur comptent comme activité), à la révocation de sa session de connexion (`revoke_login`, `ssh.session_revoked`) ou à l'arrêt. Le gestionnaire de sessions décide de ces fins ; le serveur déconnecte.


### Transferts de fichiers et redirections (jalon M2, PR 4a)

**Fonctions du droit.** Un droit SSH ouvre le terminal et les commandes. Le reste est accordé **explicitement**, fonction par fonction, par `ostena core right grant --allow <fonction>` (ADR-0014) : `transfer`, `port-forwarding`, `agent-forwarding`, `x11-forwarding`. Aucune par défaut. Le core signe les fonctions dans les droits du grant (ADR-0004 : `transfer` = dépôt et récupération, bits 2 et 3 ; redirection de ports, bit 7 ; d'agent, bit 8 ; X11, bit 9). L'agent ne lit les fonctions que dans le grant vérifié : ni le certificat, ni le client ne peuvent les étendre. Un certificat qui porte `permit-port-forwarding`, `permit-agent-forwarding` ou `permit-X11-forwarding` reste refusé (`SSH-E011`) : l'autorisation vient du droit, pas du certificat.

**Refus.** Chaque demande hors des fonctions du droit est refusée et journalisée (`ssh.request_refused`, `SSH-E022`, champs `function` et `detail`), puis notée dans le transcript (note « refus », ADR-0016), dont le core tire `access.ssh_request_refused` dans la chaîne d'audit. Une demande faite avant le début du transcript (redirection ou agent demandés avant le shell) est gardée et notée au début. La session continue : seule la demande est refusée.

**Transferts** (fonction `transfer`, les deux sens : l'agent ne distingue pas le dépôt de la récupération) :
- le sous-système `sftp` (client `sftp`, et `scp` en mode SFTP, par défaut depuis OpenSSH 9.0) ;
- les commandes `scp -t` et `scp -f` (protocole historique, `scp -O`), `rsync --server`, `sftp-server` lancé en commande ;
- toute autre commande qui **nomme** un outil de transfert (`scp`, `rsync`, `sftp-server`, en mot isolé) est refusée sans la fonction : elle pourrait faire un transfert que l'agent ne saurait pas lire. Elle est relayée normalement avec la fonction.

Avec la fonction, le transcript commence comme pour une commande (texte de la commande pour `scp` et `rsync`, chemins compris), puis porte une note « transfert » (protocole) ; l'agent journalise `ssh.transfer_started` et le core `access.ssh_transfer`. **Le contenu des fichiers n'est pas enregistré** : les sorties standard de la cible ne vont plus au transcript (les erreurs, si). Pour SFTP, l'agent lit le flux du client vers la cible avec un analyseur incrémental borné (`ostena_ssh::transfer`, messages de 256 Kio au plus, cible `cargo-fuzz` `ssh_sftp`) et note chaque opération sur un fichier **avant** de la relayer : ouverture en lecture ou en écriture, suppression, renommage (les deux chemins), création et suppression de dossier, changement d'attributs, lien. Un flux SFTP illisible coupe la session (`SSH-E023`, `ssh.transfer_unreadable`) : un transfert qu'on ne sait plus tracer n'est pas relayé.

**Redirection locale** (fonction `port-forwarding`) : un canal `direct-tcpip` (`-L`, `-W`, `ProxyJump` vers une autre machine) est ouvert **par la cible**, vers l'adresse demandée telle que la cible la joint, et relayé dans les deux sens. La cible décide aussi : la clé de l'agent déposée en `restrict` l'interdit, sauf `port-forwarding` ajouté sur la cible. Huit canaux au plus par connexion (`SSH-E019`). Chaque canal est journalisé (`ssh.forward_opened`, destination) et noté dans le transcript s'il y en a un (note « redirection », `access.ssh_forward` côté core). Ses octets sont comptés avec la session.

**Redirection distante, d'agent et X11** (fonctions `port-forwarding`, `agent-forwarding`, `x11-forwarding`) : la demande de l'utilisateur est transmise à la cible telle quelle (`tcpip-forward` avec l'adresse et le port demandés, 255 octets et 65 535 au plus, quatre ports écoutés au plus par connexion ; `auth-agent-req@openssh.com` ; `x11-req` avec le protocole et le cookie du client, 128 caractères au plus, le cookie en hexadécimal). Le cookie X11 n'est qu'un substitut : le client OpenSSH le vérifie et le remplace sur chaque canal X11, l'agent ne voit jamais le vrai. Si la cible accepte, la demande est journalisée (`ssh.forward_requested`, fonction, détail) et notée dans le transcript ; un port choisi par la cible (port 0 demandé) est rendu au client. La cible ouvre ensuite des canaux vers l'agent : `forwarded-tcpip` pour un port qu'elle écoute pour l'utilisateur, `auth-agent@openssh.com`, `x11`. Le driver les offre à la session, qui ne les accepte que pour ce que la cible a accordé (le port et l'adresse exacts d'une redirection active, l'agent, X11), dans la limite des huit canaux par connexion ; chacun est noté dans le transcript **avant** d'être relayé (refusé si la note ne peut pas être écrite), ouvert vers le client avec les mêmes paramètres, puis relayé dans les deux sens et journalisé (`ssh.forward_opened`, fonction, destination). Tout autre canal reste refusé (`ssh.target_channel_refused`). `cancel-tcpip-forward` retire la redirection côté agent avant d'être transmis. Comme pour la redirection locale, la cible décide aussi : la clé de l'agent en `restrict` coupe ces trois redirections, que l'administrateur de la cible rouvre (`port-forwarding`, `agent-forwarding`, `X11-forwarding`) seulement là où le droit les accorde.

La redirection d'agent donne à la cible l'usage des clés de l'utilisateur tant que la session dure : elle reste une fonction à accorder rarement, et chaque usage est noté (un canal par requête de la cible).

**Algorithmes offerts** : `tests/algorithms.rs` lit sur une socket le KEXINIT du serveur de l'agent (avec certificat d'hôte, comme en production) et celui du driver, l'analyse avec l'analyseur du pré-contrôle et exige que chaque nom figure dans la liste figée : `ecdh-sha2-nistp256` et les seuls marqueurs `kex-strict-*` et `ext-info-*`, clés et certificats ECDSA P-256, AES-256-GCM seul, aucun MAC, pas de compression. Il remplace un outil d'audit externe : même vérification, sans dépendance ni réseau, dans le job `ssh-interop` et avec les autres tests.

### Driver vers les cibles (`ostena_ssh::driver`)

- **Seule une `PinnedTarget` se joint** : ses adresses ont passé le contrôle de périmètre, aucune résolution de nom ici (anti-SSRF par le type). Elles sont essayées dans l'ordre.
- Pré-contrôle en client ; la clé d'hôte de la cible doit être **exactement** le point SEC1 épinglé dans l'inventaire (`SSH-E014`, `ssh.target_host_key_mismatch`) ; un certificat d'hôte de cible n'est pas accepté.
- Authentification par clé publique avec la clé de l'agent (`SSH-E015`, `ssh.target_auth_failed`).
- Tout dans le délai `target_connect_timeout` (5 s) ; cible injoignable ou négociation impossible : `SSH-E016`, `ssh.target_unreachable`.
- La bibliothèque accepte par défaut les canaux qu'un serveur ouvre vers son client : une cible ne doit jamais en ouvrir vers l'agent. Sessions, `direct-tcpip` et `streamlocal` ouverts par la cible sont refusés, comme les redirections, l'agent et X11 que l'utilisateur n'a pas demandés ou que la cible n'a pas accordés (`SSH-E017`, `ssh.target_channel_refused`).

### Configuration (`[agent.ssh]`)

| Clé | Défaut | Bornes |
|---|---|---|
| `listen` | requis | liste d'adresses `hôte:port` |
| `host_key`, `target_key`, `host_certificate` | `ssh_host_key`, `ssh_target_key`, `ssh_host_certificate` dans le dossier d'état (celui du journal anti-rejeu) | chemins absolus (`CFG-V008`) ; `host_key` et `target_key` distincts |
| `max_sessions` | obsolète : borne de l'agent si `[agent.sessions] max_sessions` est absent | 1 à 256 |
| `max_unauthenticated` | 16 | 1 à 256 |
| `max_unauthenticated_per_source` | 4 | 1 à 256 |
| `login_grace_secs` | 30 | 5 à 120 |
| `target_connect_timeout_secs` | 5 | 1 à 30 |
| `reconnect_grace_secs` | 60 | 0 à 300 ; durée de vie d'une session sans lien avec le core (ADR-0016, jalon M2) |

Les quotas et le délai d'inactivité, communs à tous les protocoles, sont dans `[agent.sessions]` (ADR-0018). Une valeur hors bornes, une adresse invalide ou la même clé pour l'hôte et les cibles donnent `CFG-V015`. Une clé SSH lisible par un autre compte, ou le dossier d'une clé pas encore créée modifiable par un autre compte, donne `CFG-P008`.

### Liaison dans l'agent (jalon M1, PR 6)

Quand `[agent.ssh]` est présent, `ostena agent run` démarre le serveur SSH à côté de la liaison au core :

- **Clés** : au premier démarrage, l'agent crée `host_key` et `target_key` par `ostena_ssh::keys` (scalaire de 32 octets tiré par `ostena-crypto`), avec des droits privés (0600 au compte du service, ACL protégée sous Windows), et journalise `agent.ssh_key_created`. L'écriture est atomique : fichier temporaire `<clé>.new` créé de façon exclusive avec les droits finaux (un reste d'écriture interrompue est d'abord supprimé, un lien comme un lien), écrit, synchronisé, puis renommé ; un arrêt pendant la création ne laisse jamais de clé tronquée. Une clé existante est relue et validée ; une clé illisible ou incohérente (`SSH-E008`), ou touchée par le défaut amont (`SSH-E007`), arrête le démarrage, avec un message qui dit quoi faire : supprimer le fichier et redémarrer, puis déposer la nouvelle clé sur les cibles (clé des cibles) ou laisser le core certifier la nouvelle clé d'hôte. `CFG-P008` les vérifie ensuite comme les autres fichiers secrets ; avant leur création, il vérifie leur dossier avec la même règle que pour le dossier d'une clé existante (modifiable seulement par le compte du service ou les administrateurs), si bien qu'en production l'agent refuse de démarrer, et donc de créer une clé, dans un dossier que d'autres peuvent modifier.
- **Clé d'hôte** : à chaque connexion au core, l'agent envoie sa clé publique d'hôte, liée à l'empreinte de son certificat mTLS (`AgentLink::subscribe_connected`, `agent.ssh_host_key_sent`). Le certificat d'hôte reçu dans `ssh_trust` est vérifié contre les autorités d'hôtes poussées avec lui (PR 5a), puis écrit dans `host_certificate` (remplacement atomique, comme les clés : fichier temporaire créé de façon exclusive, jamais à travers un lien), et l'identité SSH n'est prête qu'avec lui (`agent.ssh_identity_ready`, ou `agent.ssh_identity_refused` avec `SSH-E018`). Tant qu'elle n'est pas prête, le serveur refuse les connexions avant la bannière. La confiance est appliquée en entier ou pas du tout (fermé par défaut) : chaque push reconstruit l'identité avec ses autorités d'utilisateurs, et un push que l'agent ne peut pas appliquer (sans certificat d'hôte, certificat refusé, aucune autorité d'utilisateurs) **retire** l'identité précédente avec ses autorités (`agent.ssh_identity_refused`, `SSH-E018`, champ `withdrawn`). Les connexions déjà authentifiées continuent jusqu'à leur fin ou leur révocation. L'identité est aussi réévaluée sans attendre le push suivant, par une minuterie sur l'horloge : à la fin de validité du certificat d'hôte (l'identité est alors retirée, `agent.ssh_identity_refused`), et, pour un certificat refusé seulement parce qu'il n'est pas encore valide, au premier instant où il est accepté (son début, moins la tolérance d'horloge de 60 s).
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
| `SSH-E021` | transcript perdu (flux refusé ou arrêté par le core, tunnel coupé) : session coupée |
| `SSH-E022` | demande refusée : fonction absente du droit (transfert, redirection de ports, d'agent, X11) |
| `SSH-E023` | flux de transfert illisible : session coupée |

Événements (journal structuré, messages en français, textes du pair bornés et assainis : caractères de contrôle et de format Unicode, dont les contrôles bidirectionnels, remplacés ; aucun nom de champ masqué par la règle des journaux) : `ssh.connection_limited`, `ssh.connection_refused`, `ssh.auth_refused`, `ssh.access_refused`, `ssh.session_opened`, `ssh.exec`, `ssh.session_expired`, `ssh.session_idle`, `ssh.session_revoked`, `ssh.session_closed` (raison, octets dans chaque sens, durée), `ssh.channel_refused`, `ssh.transcript_lost`, `ssh.request_refused`, `ssh.transfer_started`, `ssh.transfer_unreadable`, `ssh.forward_requested`, `ssh.forward_opened` ; côté driver `ssh.target_host_key_mismatch`, `ssh.target_auth_failed`, `ssh.target_unreachable`, `ssh.target_channel_refused` ; côté tunnel `agent.ssh_trust_applied`, `agent.ssh_trust_refused`, `agent.login_revoked` (ADR-0008) ; côté agent `agent.ssh_started`, `agent.ssh_stopped`, `agent.ssh_unavailable`, `agent.ssh_key_created`, `agent.ssh_host_key_sent`, `agent.ssh_host_key_unsent`, `agent.ssh_identity_ready`, `agent.ssh_identity_refused`, `agent.login_revocation_applied`, `agent.session_report_lost`, `agent.transcript_lost`, `ssh.revocations_lost` ; côté file des bilans (ADR-0012, PR 11d) `agent.report_queue_full`, `agent.report_queue_unreadable`, `agent.report_queue_write_failed`, `agent.report_unsent`. Les événements du serveur portent l'adresse du client (`peer`) et celle d'écoute (`listener`).

### Défaut amont : clés P-256 à scalaire court

`ssh-key 0.7.0-rc.11`, imposée par russh, refuse une clé privée P-256 dont OpenSSH encode le scalaire sur **31 octets ou moins** : `Encoding(Length)`. OpenSSH écrit le scalaire en `mpint` minimal. Il tombe à 31 octets quand son premier octet est nul et que le deuxième est inférieur à 0x80, soit environ **une clé sur 512** produite par `ssh-keygen`. Constaté sur 600 clés générées (une refusée), confirmé par décodage de la clé fautive et par un test qui fabrique une telle clé. OpenSSH l'accepte ; seul `ssh-key` la refuse. Les clés à 32 ou 33 octets passent.

- **Les clés de l'agent et celles d'`ostena login`** sont générées par `ostena-crypto` (aws-lc-rs), jamais par `ssh-key` ni par `rand` (`ostena_ssh::keys`). Le scalaire occupe 32 octets : un scalaire dont le premier octet est nul est tiré à nouveau, ce qui coûte moins de 0,006 bit sur 256. Imposer un `mpint` de 32 octets avec un zéro de tête superflu n'est pas possible : il ne serait pas canonique, et OpenSSH le refuse.
- **Une clé importée par un administrateur et touchée par le défaut** est refusée avec un message explicite (`SSH-E007` : « clé P-256 refusée : son scalaire privé est encodé sur 31 octets… générez-en une nouvelle, ou laissez Ostena générer la clé ») plutôt qu'une erreur de format.
- **Tests** : un test par propriétés vérifie que toute clé générée est relue par `ssh-key` et acceptée par OpenSSH (`ssh-keygen -y`). Un test documente le défaut (clé à 31 octets refusée par `ssh-key`, acceptée par OpenSSH) ; il échouera quand `ssh-key` sera corrigé, signal pour retirer le contournement.
- Les tests et les scripts qui passent par `ssh-keygen` régénèrent une clé que russh ne sait pas lire.
- À signaler en amont, et à revérifier avec `ssh-key` 0.7 stable : c'est l'un des critères de réexamen de l'ADR-0009.

### Limites et écarts connus (jalon M1, PR 4)

- ~~**Le grant ne signe ni le compte ni la session de connexion.**~~ **Levée à la PR 5a** : le grant v2 (ADR-0004) porte une liaison de 128 bits à la session de connexion et au compte, que l'agent recalcule et exige après avoir consommé le jti (`TUN-E010`, grant brûlé). Le contrôle du compte dans `session_params` reste.
- ~~**`ssh.exec` journalise un SHA-256 simple** de la commande~~ : **levée à la PR 8**. L'agent ne journalise que la longueur ; le core consigne un HMAC-SHA-256 sous sa clé d'empreinte des commandes (`access.ssh_exec`, ADR-0016).
- **Requêtes relayées une à une** : la bibliothèque ne garde qu'un indicateur « réponse attendue » par canal, si bien que chaque requête (terminal, shell, commande, environnement) est transmise à la cible et sa réponse attendue dans le rappel, jusqu'à 10 s, en bloquant la boucle de la connexion. Une seule file de réponses par canal.
- **Adresses de la cible essayées l'une après l'autre** par le driver, dans le délai global de 5 s : une première adresse muette peut consommer tout le délai.
- **Flux couplés** : la bibliothèque traite une connexion dans une seule boucle ; un flux montant et un flux descendant tous deux massifs et couplés (une cible qui ne lit plus tant qu'elle ne peut écrire) peuvent se bloquer mutuellement au-delà des tampons. Le terminal et les commandes usuelles ne sont pas concernés ; à revoir avec les transferts de fichiers.
- **Aucune tolérance d'horloge sur le début de validité** : la bibliothèque refuse un certificat dont le début est encore à venir avant nos contrôles ; la marge de 60 s de `check_user` n'est qu'une défense en profondeur.
- ~~**Clé de la CA d'hôte**~~ : **levée à la PR 5a**. `ssh_trust` porte les autorités d'hôtes (`host_ca_p256_public`, 1 à 4) et l'agent vérifie la signature de son certificat d'hôte (`SSH-E018`).
- **Core réel** : depuis la PR 5b, le core décide de l'accès depuis son inventaire, certifie la clé d'hôte et diffuse les révocations (ADR-0014). Un droit révoqué n'y coupe pas les sessions ouvertes ; la révocation de la session de connexion, si.
- **Chemins par défaut des clés SSH** : confirmés à la PR 6, dans le dossier d'état (celui du journal anti-rejeu).
- **Révocations perdues par le consommateur** : levée à la PR 6 (`SSH-E020`, toutes les sessions coupées).

### Limites et écarts connus (jalon M1, PR 6)

- **Révocations perdues pendant une coupure du tunnel** : un `login_revoked` émis par le core pendant que la liaison est coupée n'arrive pas à l'agent sur le moment. Pas de coupure automatique au jalon M1 (décision du responsable du projet). Depuis la PR 5b, le core repousse à chaque reconnexion les révocations non expirées des sessions de connexion pour lesquelles l'agent a reçu ou consommé un grant, ce que l'agent traite de façon idempotente (ADR-0014). ~~Les sessions SSH en cours continuent donc au plus jusqu'au retour de la liaison.~~ **Levée à la PR 8** (décision du responsable du projet, ADR-0016) : le flux du transcript appartient à la connexion du tunnel, et sa perte coupe les sessions SSH en cours (`SSH-E021`). Il n'y a donc plus de session SSH ouverte pendant une coupure.
- **Adresses locales relevées au démarrage** : le contrôle de périmètre de l'agent prend un instantané de ses propres adresses au démarrage, sans le rafraîchir. Une adresse ajoutée ensuite n'est pas reconnue comme locale avant un redémarrage.
- **Test de bout en bout hors de l'hôte** : le plancher du périmètre refuse la boucle locale et les adresses de l'agent, et une politique poussée ne peut pas le lever. Le parcours complet du test `agent_ssh` (session, révocation, clé hôte de la cible inattendue) demande donc une cible sur une autre machine : un conteneur Debian 12 en CI (`tests/ssh/native-e2e.sh`), ou une cible donnée par les variables `OSTENA_E2E_*`. Sans elles, le test vérifie la mise en place et les refus (certificat expiré, ressource inconnue, cible en boucle locale).

### Limites et écarts connus (jalon M2, PR 4a)

- **Le shell peut toujours déplacer des données** : un terminal ou une commande ordinaire peut afficher un fichier (`cat`, `base64`) ou en recevoir un. Ce qui s'affiche est dans le transcript ; ce qui est tapé ne l'est pas (pas de frappes au jalon M1). Les fonctions encadrent les protocoles de transfert, pas toute sortie de données.
- **Aucun sens imposé** : la fonction `transfer` permet le dépôt et la récupération. Les bits du grant les distinguent déjà (2 et 3) ; l'agent ne lit pas encore assez le protocole de `scp` ou de `rsync` pour n'en laisser passer qu'un.
- **Noms de fichiers de `rsync`** : son protocole n'est pas analysé. Le transcript porte sa commande (chemins côté cible) et la note de transfert, pas la liste des fichiers. De même pour le `scp` historique, dont seuls les chemins de la commande sont connus.
- **Redirection sans session** : un `ssh -W` ou un `ProxyJump` n'ouvre pas de canal de session, donc pas de transcript ; le canal n'est tracé que par le journal de l'agent (`ssh.forward_opened`) et le bilan de la session (octets).
- **Commande nommant un outil** : la détection est lexicale (mot isolé) ; un outil renommé ou un interpréteur qui reconstruit son nom n'est pas reconnu. C'est une aide, pas une frontière : la frontière reste le droit sur le compte et ce que la cible permet.

## Conséquences

- **Interopérabilité vérifiée** :
  - client OpenSSH 9.x vers le serveur de l'agent : la session aboutit, et un client limité à des algorithmes hors liste est refusé ;
  - client de l'agent vers un sshd OpenSSH 9.2 de Debian 12 (`tests/ssh/debian12-target.sh`), avec une clé déposée en `restrict,from=` : la session aboutit, et une clé hôte inattendue est refusée ;
  - client OpenSSH (9.5 sous Windows, 9.2 sous Debian 12) avec un certificat, `@cert-authority` et `StrictHostKeyChecking=yes`, à travers le serveur de l'agent jusqu'à une cible (`tests/interop.rs`) : la session aboutit ; sont refusés une autorité d'hôte non reconnue, une clé nue, une autre autorité d'utilisateurs, un certificat expiré, `permit-port-forwarding`, un nom sans ressource, un refus de l'autorisation ; sans les fonctions du droit, `-W` (`direct-tcpip`, comme `-L`), `-R`, `-s sftp` et la redirection d'agent (`SSH-E022`) ; la durée maximale et la révocation coupent la session ;
  - transferts avec les vrais outils OpenSSH (`tests/transfers.rs`, Unix) vers une cible qui lance le vrai `sftp-server`, `scp` et `rsync` : `scp` dans les deux protocoles et les deux sens, `sftp` (création, dépôt, renommage, récupération, suppression, dans l'ordre dans le transcript), `rsync` ; sans la fonction, tous refusés et rien n'atteint la cible ; le contenu des fichiers n'est jamais dans le transcript ; `ssh -W` relayé avec la fonction de redirection, refusé sans ;
  - le parcours complet par le tunnel et le core de test (`tests/gateway.rs`) : jti consommé des deux côtés, rejeu refusé, sujet ou compte différents (`TUN-E010`), clé hôte absente, cibles de métadonnées ou de boucle locale refusées par le périmètre, rien sans confiance poussée (`TUN-E026`) ;
  - de bout en bout (`tests/ssh/native-e2e.sh`, test `agent_ssh` d'`ostena-cli`) : client OpenSSH, binaire `ostena agent run` réel avec `[agent.ssh]`, tunnel, core de test, driver, sshd Debian 12 avec la clé de l'agent en `restrict,from=` ; la révocation coupe la session et une clé hôte de cible inattendue est refusée (`SSH-E014`).
- **Latence ajoutée** mesurée par `cargo bench -p ostena-ssh --bench relay` (aller-retour de 64 octets dans un shell, à travers le serveur et le driver, comparé au même aller-retour direct vers la cible, en boucle locale) : **120 µs au p99 sous Windows 11** et **52 µs au p99 sous Linux** (conteneur Docker, WSL2), pour un objectif de 3 ms. Établissement d'une session complète (contrôles du certificat, autorisation, connexion à la cible, canal, shell) : 5,6 ms au p50 sous Windows, 5,1 ms sous Linux, pour un objectif de 5 s. Les sockets du serveur et du driver sont en `TCP_NODELAY` : sans cela, Nagle et les accusés de réception différés ajoutaient environ 100 ms à l'établissement sous Linux. Affiché en CI sans seuil bloquant (ADR-0005).
- **Clients exclus** : un client trop ancien pour le strict KEX ou pour AES-GCM est refusé. C'est voulu.
- **Le grant n'apparaît pas** dans le parcours SSH de l'utilisateur. Pour RDP, il reste remis à l'utilisateur (ADR-0004).
