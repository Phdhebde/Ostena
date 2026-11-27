# ADR-0007 : Service de l'agent passerelle et plan de contrôle local

- **Statut** : Accepté
- **Date** : 2026-11-11
- **Révision** : 2026-11-11, support Linux à partir de Debian 12 (systemd 252), Debian 11 abandonné
- **Révision** : 2026-11-25, serveur SSH natif dans le service (`AGT-E010`, arrêt, statut), empreinte mesurée avec et sans SSH, seuil bloquant (jalon M1, PR 6)
- **Révision** : 2026-11-26, service Windows en démarrage automatique différé, et `ostena agent setup` pour les paquets (ADR-0024, jalon M2, PR 18)

## Contexte

L'agent passerelle tourne en service sur Windows Server (2016 à 2025) et sur Debian (12 et plus). Il détient une clé privée mTLS et un journal anti-rejeu, il ouvre des sessions vers des cibles sensibles, et il doit pouvoir être interrogé localement par un administrateur. Il doit s'installer sans interaction, tourner avec le minimum de droits, ne pas redémarrer en boucle, s'arrêter proprement et rester léger. Seul `ostena-platform` peut contenir du code `unsafe` (CLAUDE.md).

## Décision

### Un binaire, des sous-commandes

`ostena agent install | uninstall | run | status` :
- **`install`** est non interactive et peut être relancée (idempotente) : elle enregistre le service, pose les droits des fichiers et démarre le service, sauf avec `--no-start`. `--quiet` supprime toute sortie en cas de succès ;
- **`uninstall`** arrête et désinscrit le service, mais garde la configuration, les données et le compte ;
- **`status`** sort avec le code 0 si le service tourne, 3 s'il est arrêté, 4 s'il n'est pas installé.

Un trait commun, `ServiceManager`, masque la différence entre le SCM et systemd.

### Windows : compte virtuel `NT SERVICE\OstenaAgent`

- **Compte** : le service tourne sous son **compte virtuel**. C'est un compte dédié, géré par Windows, sans mot de passe, avec un SID propre qui sert à cibler les ACL. `LocalService` est écarté parce qu'il est partagé avec d'autres services.
- **Pourquoi pas SYSTEM** : il n'est pas nécessaire. L'agent ne lie aucun port privilégié (il n'y en a pas sous Windows), ne modifie pas la configuration du système, et s'authentifie auprès des cibles avec les identifiants fournis par le coffre, jamais avec sa propre identité.
- **Identité réseau, et ce que ça implique pour Kerberos** : un compte virtuel **s'authentifie sur le réseau comme le compte machine du domaine** (`DOMAINE\HÔTE$`).
  - Tout accès réseau que l'agent fait en son nom propre (DNS, LDAP, partages, résolution, futur tunnel vers le core) apparaît comme celui de l'ordinateur passerelle. Ses tickets Kerberos sont ceux du compte machine.
  - **Ne jamais accorder de droits sur les cibles au compte machine des passerelles**, et **ne jamais configurer de délégation Kerberos sur ce compte**. Une délégation non contrainte sur une passerelle permettrait à quiconque la compromet de se faire passer pour les utilisateurs qui s'y authentifient.
  - Les sessions vers les cibles utilisent les identifiants délégués par le coffre (CredSSP, Kerberos avec les identifiants de l'utilisateur ou du compte de service cible) et les SPN des cibles. Le compte machine n'y intervient pas.
  - Si un client impose un compte de domaine dédié, une option `--account` permettra un gMSA, qui obéit aux mêmes règles : aucune délégation, aucun droit sur les cibles.
- **SID de service restreint** (`SERVICE_SID_TYPE_RESTRICTED`) : le jeton du service ne passe un contrôle d'accès que si la ressource autorise aussi son SID de service. Tout ce que le service touche reçoit donc une ACL explicite.
- **Privilèges requis** : seulement `SeChangeNotifyPrivilege`. `windows-service` ne gère pas ce réglage ; il passe par `ChangeServiceConfig2W`, en `unsafe`, dans `ostena-platform`. Tous les autres privilèges sont retirés du jeton.
- **ACL posées par `install`** :
  - configuration : SYSTEM et Administrateurs en contrôle total, le service en lecture seule ;
  - dossier de configuration : protégé de la même façon s'il est dédié (`…\Ostena`) ; un autre dossier n'est pas modifié ;
  - clé privée : lecture pour le service seul (`CFG-P008`) ;
  - dossier d'état : modification pour le service (`CFG-P009`).

  Le propriétaire de ces objets est le groupe Administrateurs.
- **Démarrage** : automatique différé (`AUTO_START (DELAYED)`, ADR-0024) : l'agent démarre une fois les services du démarrage en place.
- **Redémarrage borné** : actions d'échec du SCM, 3 redémarrages après 5 s, compteur remis à zéro après 600 s, puis aucune action. Le service reste alors arrêté, et le SCM journalise les événements 7031 et 7034. Les échecs qui ne sont pas des plantages déclenchent aussi ces actions.
- **Arrêt** : le service annonce `STOP_PENDING` avec un délai indicatif de 330 s (délai de grâce maximal de 300 s, plus une marge).

### Linux : utilisateur `ostena`, unité durcie

- **Compte** : utilisateur système `ostena`, sans shell ni répertoire personnel, créé par `install`.
- **Droits posés par `install`** :
  - configuration : `root:ostena 0640` ;
  - clé privée : `ostena:ostena 0600` ;
  - unité : `/etc/systemd/system/ostena-agent.service`.
- **Directives de l'unité** :
  - `Type=notify` (`READY=1` et `STOPPING=1` écrits sur le socket systemd par la bibliothèque standard, sans `unsafe`) ;
  - `User=ostena`, `UMask=0077` ;
  - `StateDirectory=ostena` en `0700` pour le journal anti-rejeu, `RuntimeDirectory=ostena` en `0700` pour le socket ;
  - `NoNewPrivileges`, `CapabilityBoundingSet=` et `AmbientCapabilities=` vides (rien n'écoute encore sur un port privilégié ; `CAP_NET_BIND_SERVICE` seul sera ajouté le jour où ce sera le cas) ;
  - `ProtectSystem=strict`, `ProtectHome`, `PrivateTmp`, `PrivateDevices`, `ProtectKernel*`, `ProtectControlGroups`, `ProtectClock`, `ProtectHostname`, `ProtectProc=invisible`, `ProcSubset=pid` ;
  - `RestrictNamespaces`, `RestrictRealtime`, `RestrictSUIDSGID`, `LockPersonality`, `MemoryDenyWriteExecute`, `RemoveIPC`, `KeyringMode=private` ;
  - `SystemCallArchitectures=native`, `SystemCallFilter=@system-service ~@privileged @resources` ;
  - `RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK` (le netlink sert à lister les interfaces, pour le plancher du périmètre).
- **Redémarrage borné** : `Restart=on-failure`, `RestartSec=5`, `StartLimitIntervalSec=600`, `StartLimitBurst=3`. Au-delà, l'unité passe en `failed` et systemd journalise « Start request repeated too quickly ».
- **Isolation complémentaire** : `PrivateIPC` (systemd 248) et `PrivateMounts`. `PrivateUsers` est écarté : une capacité détenue dans un espace de noms utilisateur privé ne vaut pas pour le réseau de l'hôte, ce qui empêcherait le futur `CAP_NET_BIND_SERVICE`.
- **Compatibilité : Debian 12 (systemd 252) au minimum.** Debian 11 n'est plus pris en charge : il est en fin de vie, et ses paquets ne sont plus que sur `archive.debian.org`. L'unité générée passe `systemd-analyze verify` sous systemd 252 sans aucun message, et obtient un score `systemd-analyze security` de **1,3 « OK »** sous systemd 252 (cycle de vie complet vérifié sous cette version).
- **Directives écartées pour l'instant** :
  - `RestrictFileSystems` exige le LSM BPF, absent par défaut du noyau Debian ;
  - `SocketBindDeny` gênerait le socket UDP du futur tunnel QUIC.

  Les deux sont à revoir avec le tunnel.

### Plan de contrôle local

- **Points d'accès** :
  - Linux : `/run/ostena/agent.sock` ;
  - Windows : `\\.\pipe\ostena-agent` ;
  - configurables par `agent.control_endpoint`, contrôlé par `CFG-V011`.
- **Linux** :
  - socket en mode 0600, dans un dossier en mode 0700, appartenant au compte du service ;
  - le serveur vérifie l'uid de l'appelant (`SO_PEERCRED`) : root ou le compte du service, les autres sont refusés et journalisés (`agent.control_denied`) ;
  - le client vérifie, avant de parler, que le socket et son dossier appartiennent à root ou au compte du service (`AGT-E007`) ;
  - un socket déjà actif refuse le démarrage d'un second agent (`AGT-E006`) ; un socket abandonné est remplacé.
- **Windows, contre le squat du nom** :
  - la première instance est créée avec `FILE_FLAG_FIRST_PIPE_INSTANCE` : si le nom existe déjà (autre agent ou squat), l'agent **refuse de démarrer** (`AGT-E006`, événement `agent.control_unavailable`) ;
  - `PIPE_REJECT_REMOTE_CLIENTS` est activé ;
  - DACL protégée `D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;OW)` plus le SID du service : un utilisateur standard est refusé (`AGT-E009`) ;
  - côté client, `ostena agent status` vérifie avec `GetNamedPipeServerProcessId` que **le processus serveur est bien le service `OstenaAgent`** (pid rapporté par le SCM) avant de lire la réponse (`AGT-E007`).
- **Protocole** : une requête JSON et une réponse JSON, chacune précédée de sa longueur sur 4 octets, 4 Kio au plus, 1 s de délai.
- **Commandes en lecture seule** : `status` (état, version, durée de fonctionnement, groupe, connexion au core, sessions, mémoire résidente, empreinte SHA-256 du fichier de configuration chargé), `version` et `config_fingerprint`. Toute autre commande est refusée. **Une commande qui modifierait l'état exigera une authentification locale** (à définir dans un ADR ultérieur).

### Arrêt propre

Sur `SIGTERM` ou `SIGINT`, Ctrl-C, ou l'arrêt par le SCM, l'agent suit cette séquence :
1. il passe en arrêt (`STOPPING=1` pour systemd) et refuse les nouvelles sessions ;
2. il demande aux sessions en cours de se terminer et leur laisse `agent.shutdown_grace_secs` (1 à 300 s), puis interrompt les autres. Le serveur SSH natif (ADR-0010) cesse d'écouter et déconnecte ses sessions dans le même délai, qui couvre toutes les sessions (pas un délai par type) ; leur fin, y compris celle des sessions en cours d'autorisation, est signalée au core avant la fermeture du lien, dans ce délai (`agent.ssh_stopped`) ;
3. il ferme le plan de contrôle (le socket est supprimé) ;
4. il fait un `fsync` du journal anti-rejeu et libère son verrou.

Événements émis : `agent.stopping`, `agent.sessions_closed` (terminées et interrompues), `agent.stopped`.

### Empreinte mémoire

`agent.idle_footprint` est journalisé 5 s après le démarrage, avec la mémoire résidente (`VmRSS` sous Linux, *working set* sous Windows). `cargo xtask footprint` lance l'agent optimisé dans trois états et l'affiche : sans lien avec le core, lien configuré mais core injoignable, et connecté à un core de test (l'exemple `test_core` d'`ostena-tunnel`, dans son propre processus, jamais dans le binaire `ostena`). Sous Linux, il détaille la mémoire anonyme, la mémoire adossée à des fichiers et le nombre de threads.

Mesures au repos, pour un objectif indicatif de 20 Mio :

| État | Linux (Debian, conteneur) | Windows 11 |
|---|---|---|
| sans lien | 3,9 Mio (anonyme 0,4 ; fichiers 3,6 ; 5 threads) | 6,7 Mio |
| non connecté | 5,4 Mio (anonyme 0,5 ; fichiers 5,0 ; 5 threads) | 9,5 Mio |
| connecté | 5,3 Mio (anonyme 0,5 ; fichiers 4,9 ; 5 threads) | 10,2 Mio |

Le lien coûte environ 1,5 Mio sous Linux et 3,4 Mio sous Windows. **Presque tout est du code** : les pages de la pile QUIC/TLS et d'aws-lc dans l'exécutable, partagées et en lecture seule, et, sous Windows, `mswsock.dll`, chargée par la première socket UDP. Sous Windows, la liste des adresses de l'agent (`GetAdaptersAddresses`, nécessaire au plancher du contrôle de périmètre) charge aussi `NSI.dll`, `dhcpcsvc.dll`, `dhcpcsvc6.dll` et `DNSAPI.dll` : environ 0,9 Mio de pages partagées. La mémoire anonyme ne croît que d'environ 100 Kio (tampons QUIC, configuration TLS) ; la mémoire privée Windows passe de 1,3 à 2,0 Mio ; le nombre de threads ne change pas. Aucune part évitable n'a été trouvée. Une mesure prise pendant un autre build sur la même machine est faussée (11,5 Mio relevés ainsi sous Windows) : mesurer sur une machine au repos.

**Seuil de régression** (décidé le 2026-11-14) : une régression d'empreinte n'est bloquante que si elle dépasse à la fois **+10 % et 1 Mio** en valeur absolue. Sur une base de quelques Mio, 10 % seuls déclencheraient pour quelques centaines de Kio de pages d'image.

**Avec et sans SSH** (jalon M1, PR 6) : `cargo xtask footprint` mesure chaque état deux fois. La référence est un agent construit sans le serveur SSH (fonctionnalité `ssh` d'`ostena-cli` coupée, pour cette mesure seulement : `check-release` refuse un binaire de release sans elle). L'autre mesure est l'agent de release avec `[agent.ssh]` à l'écoute. La commande **échoue**, donc la CI aussi, si l'agent avec SSH dépasse la référence de +10 % et de 1 Mio à la fois, s'il charge une bibliothèque ou une DLL que la référence ne charge pas, ou une DLL d'interface graphique ou COM (ADR-0009). Les autres bancs restent affichés sans seuil (ADR-0005).

### Codes et événements

| Code | Erreur |
|---|---|
| `AGT-E001` | droits administrateur ou root nécessaires |
| `AGT-E002` | installation impossible |
| `AGT-E003` | désinstallation impossible |
| `AGT-E004` | état du service indisponible |
| `AGT-E005` | échec de l'exécution sous le gestionnaire de services |
| `AGT-E006` | nom du plan de contrôle déjà pris (autre agent ou squat) |
| `AGT-E007` | serveur du plan de contrôle non authentique |
| `AGT-E008` | erreur d'entrée-sortie, délai ou taille sur le plan de contrôle |
| `AGT-E009` | accès au plan de contrôle refusé |
| `AGT-E010` | adresse d'écoute du serveur SSH natif inutilisable (`agent.ssh.listen`) : l'agent refuse de démarrer |
| `AGT-E013` | sessions Bureau à distance d'une cible impossibles à lister ou à fermer (API WTS, agent Windows seulement ; ADR-0026) |
| `AGT-E014` | ticket Kerberos impossible pour le service de gestion des sessions d'une cible (`cifs/<nom>`, SSPI ; ADR-0026) |

Événements : `agent.started`, `agent.stopping`, `agent.sessions_closed`, `agent.stopped`, `agent.idle_footprint`, `agent.config_refused`, `agent.replay_store_refused`, `agent.control_unavailable`, `agent.control_denied`, `agent.control_error` ; pour le serveur SSH natif (ADR-0010) : `agent.ssh_started`, `agent.ssh_unavailable`, `agent.ssh_key_created`, `agent.ssh_stopped`.

### `unsafe` dans `ostena-platform`

Le lint `clippy::undocumented_unsafe_blocks` y est actif. Chaque bloc a un commentaire `SAFETY:` et un test :

| Appel | Test |
|---|---|
| `GetNamedSecurityInfoW`, `GetAce`, `ConvertSidToStringSidW`, `LocalFree` (lecture des ACL) | `acl::tests::windows` (ACL posées par `icacls`) |
| `LookupAccountNameW` | `well_known_accounts` |
| `ConvertStringSecurityDescriptorToSecurityDescriptorW`, `CreateNamedPipeW` avec attributs de sécurité, `GetNamedPipeServerProcessId` | `control::tests` (squat, identité du serveur, DACL) |
| `GetProcessMemoryInfo` | `memory::tests` |
| `ChangeServiceConfig2W` (privilèges requis) | job CI `agent-windows` (`sc qprivs`) |

## Conséquences

- **Tests d'intégration en CI** :
  - `agent-linux` exécute le cycle complet sous un vrai systemd : installation de production, droits, `status` (refusé à un utilisateur non root), score de durcissement, arrêt propre, redémarrages bornés, désinstallation, puis vérification stricte de l'unité sous Debian 12 et empreinte ;
  - `agent-windows`, sur Windows Server 2025 et 2022, vérifie le compte, le SID restreint, les privilèges, les actions d'échec, les ACL, `status`, le **refus du pipe à un utilisateur non administrateur**, l'arrêt propre et la désinstallation.
- **Windows Server 2016** n'est pas disponible en CI. Il est vérifié à la main (essai S5, `docs/exploitation/agent-installation.md`). Si le SID restreint y bloque quelque chose, on en reparle avant d'assouplir.
- **Debian 11 est abandonné** (révision du 2026-11-11) : CLAUDE.md exige désormais Debian 12 et plus. Une passerelle sous Debian 11 doit être migrée avant d'installer l'agent.
- **Les comptes intégrés sont identifiés par SID** et jamais par nom, ces noms étant traduits selon la langue de Windows.
- **Contrainte d'administration Active Directory** : comme le compte machine des passerelles porte l'identité réseau de l'agent, l'administration AD doit s'interdire toute délégation et tout droit sur ce compte. La fiche d'exploitation le rappelle.
