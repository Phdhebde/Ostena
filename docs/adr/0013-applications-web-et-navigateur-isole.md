# ADR-0013 : Applications web par navigateur isolé

- **Statut** : Proposé
- **Date** : 2026-11-16

## Contexte

Une bonne part de l'administration passe par des consoles web : hyperviseurs, contrôleurs de serveurs (BMC), équipements réseau et de stockage, supervision, consoles d'automates et d'IHM en environnement industriel. Le grant prévoit déjà le protocole 4 « Web » (ADR-0004) et le framing prévoit les sessions « application web » dans le portail (ADR-0006). Reste à décider comment la passerelle les sert.

Deux approches sont possibles :

- **Proxy HTTP inverse** : la passerelle relaie les requêtes, et c'est **le navigateur de l'administrateur qui exécute** le HTML et le JavaScript de la console. C'est léger. Mais une console compromise, ou simplement vulnérable (XSS, dépendance JavaScript piégée), exécute alors son code sur le poste d'administration, celui qui détient les accès les plus sensibles. Le proxy doit aussi réécrire les URL, les cookies et les en-têtes `Origin` pour faire passer la cible sous l'origine du portail, ce qui crée une surface de confusion entre le portail et les cibles.
- **Navigateur isolé** : un navigateur tourne sur la passerelle, dans un bac à sable jetable propre à la session. Le poste d'administration ne reçoit que des images et n'envoie que des entrées clavier et souris, par les trames de l'ADR-0006, comme pour RDP ou VNC. Aucun code de la cible ne s'exécute sur le poste.

Contraintes particulières :

- **Empreinte** : un navigateur coûte des centaines de Mio par session. C'est sans commune mesure avec les quelques Mio de l'agent (ADR-0007).
- **Latence** : la cible est de 10 ms ajoutées au p99 côté navigateur, alors qu'il faut capturer et encoder l'écran.
- **Unité de l'agent** : elle est durcie avec `MemoryDenyWriteExecute`, `RestrictNamespaces` et un filtre d'appels système (ADR-0007). Ces protections s'héritent : un navigateur lancé par l'agent ne peut ni compiler son JavaScript à la volée ni créer son propre bac à sable. Il ne faut pas les retirer de l'agent.
- **Périmètre** : le contrôle de l'ADR-0005 s'applique à tous les drivers. Or un navigateur ouvre des connexions de lui-même (sous-ressources, redirections) et résout les noms lui-même.
- **Hors ligne** : le navigateur n'est pas une dépendance Cargo. `cargo deny` ne le contrôle pas, et il faut pouvoir le mettre à jour en air gap.

## Décision

### Navigateur isolé uniquement

`ostena-webproxy` sert les applications web **uniquement par navigateur isolé**. Le proxy HTTP inverse est écarté : il ferait exécuter le code des cibles sur le poste d'administration, ce qui va contre l'objectif même du bastion. Il n'existe donc pas d'accès « natif » aux applications web : elles passent toujours par le portail.

Le navigateur est **Chromium**, sans affichage (`--headless`), piloté par le **Chrome DevTools Protocol** (CDP). C'est un logiciel libre (licence BSD), il est disponible dans les dépôts Debian, et le CDP fournit tout ce qu'il faut : capture de l'écran, injection des entrées, interception des téléchargements et des sélecteurs de fichiers.

### Linux seulement

Le rôle n'existe que sur l'agent **Debian 12+**. Sous Windows, la configuration qui l'active est refusée au démarrage. Un bac à sable de même niveau sous Windows (AppContainer, objets job, pare-feu par processus) demandera un ADR à part.

### Séparation des privilèges : un service d'isolement

Le navigateur n'est **jamais un enfant du processus de l'agent**. Un second service, `ostena-webiso`, lancé par le même binaire (`ostena webiso run`), s'en charge :

- **Compte** : utilisateur système `ostena-web`, distinct d'`ostena`. Il n'a accès ni à la clé de l'agent, ni à sa configuration, ni au journal anti-rejeu.
- **Unité** : mêmes protections que l'agent, sauf trois qui sont levées parce que le bac à sable en a besoin :
  - `RestrictNamespaces` autorise les espaces de noms utilisateur, réseau, montage, PID et IPC ;
  - `SystemCallFilter` admet ce qu'il faut pour les créer ;
  - `MemoryDenyWriteExecute` est conservé si le prototype montre que Chromium en mode sans JIT (voir plus bas) fonctionne avec, et retiré sinon. La mesure tranchera, et cet ADR sera complété en conséquence.
- **Dialogue** : l'agent parle au service par un socket Unix dans `/run/ostena-webiso/` (mode 0660, groupe partagé), avec contrôle de l'uid de l'appelant (`SO_PEERCRED`), comme pour le plan de contrôle (ADR-0007). L'agent envoie la description de la session (URL de départ, origines autorisées, empreintes épinglées, droits, limites) et reçoit en retour le flux CDP.
- **Absence de pouvoir** : le service ne voit ni grant, ni secret, ni le core. C'est l'agent qui vérifie le grant et qui décide.

### Bac à sable de chaque session

Pour chaque session, le service crée un processus dans de **nouveaux espaces de noms utilisateur, réseau, montage, PID et IPC**, puis y lance Chromium. Le code qui crée ces espaces de noms vit dans `ostena-platform`, seule crate autorisée à utiliser `unsafe` (avec `// SAFETY:` et un test par bloc).

- **Système de fichiers** : racine en lecture seule. Le profil Chromium (`--user-data-dir`) et le dossier de téléchargement sont dans un `tmpfs` propre à la session, détruit à la fin. Aucun état ne survit d'une session à l'autre : ni cookies, ni cache, ni mots de passe.
- **Réseau** : l'espace de noms réseau ne contient **que la boucle locale**. La seule sortie est un relais qui écoute sur `127.0.0.1` dans la session et transmet au proxy de périmètre de l'agent (paragraphe suivant), par un socket Unix sur le système de fichiers.
- **Ressources** : un cgroup v2 par session, avec un plafond de mémoire (`memory.max`), de CPU (`cpu.max`) et de nombre de processus (`pids.max`). Dépasser le plafond de mémoire tue la session, pas l'agent.
- **Bac à sable propre de Chromium** : il reste actif. `--no-sandbox` est interdit, sans option pour le permettre.
- **Pilotage** : le CDP passe par `--remote-debugging-pipe` (descripteurs 3 et 4). **Aucun port de débogage n'est ouvert**, même sur la boucle locale.
- **JavaScript sans JIT** : Chromium est lancé avec `--js-flags=--jitless`. Cela retire la compilation à la volée, d'où vient une grande partie des failles exploitées dans les moteurs JavaScript, au prix de performances moindres sur les consoles lourdes.

### Politique de Chromium

Une politique gérée, montée en lecture seule dans l'espace de noms de montage de la session, fixe :

- les seuls schémas `https` et `http` vers les origines autorisées (`URLAllowlist`), tout le reste étant bloqué (`URLBlocklist` à `*`), y compris `file:`, `chrome:` et `devtools:` ;
- outils de développement, extensions, gestionnaire de mots de passe, remplissage automatique, synchronisation, impression et audio désactivés ;
- QUIC désactivé (`--disable-quic`) : tout passe par le proxy de périmètre en TCP.

### Proxy de périmètre dans l'agent

Chromium est configuré pour tout envoyer à un proxy HTTP (`--proxy-server`). **Ce proxy tourne dans l'agent**, pas dans le service d'isolement. Il n'accepte que `CONNECT hôte:port` (et les requêtes HTTP en clair si la cible est déclarée en `http`) et, pour chaque connexion :

1. vérifie que l'hôte et le port font partie des **origines autorisées de la session** ;
2. passe la cible par `ostena-scope` : analyse stricte, résolution unique, plancher, épinglage de l'adresse (ADR-0005) ;
3. se connecte uniquement à l'adresse épinglée.

Chromium ne résout donc jamais un nom lui-même, et le contrôle de périmètre s'applique à chaque sous-ressource et à chaque redirection, pas seulement à l'URL de départ. Le proxy **ne déchiffre pas TLS** : il n'a pas besoin de crypto, et la vérification du certificat de la cible reste à Chromium.

L'analyseur des requêtes `CONNECT` lit des données réseau : il a sa cible `cargo-fuzz`.

### Certificats des cibles

Sécurité par défaut, comme pour RDP (ADR-0003) : une cible web doit présenter un certificat valide pour la PKI du client, ou une clé épinglée.

- **PKI du client** : les autorités de la configuration sont importées dans le magasin du profil de la session.
- **Épinglage** : pour une cible sans PKI (certificat autosigné d'un contrôleur de serveur, par exemple), l'inventaire porte l'empreinte SHA-256 de la clé publique (SPKI), passée à Chromium par `--ignore-certificate-errors-spki-list`. Seule cette clé est acceptée, et seulement pour cette session.
- **Refus** : ignorer toutes les erreurs de certificat n'est pas proposé.

### Affichage et entrées

- **Affichage** : capture par `Page.startScreencast`, en JPEG (codec `Jpeg` de l'ADR-0006), chaque image acquittée (`Page.screencastFrameAck`). Cet acquittement régule le débit naturellement : Chromium n'envoie pas plus d'images que le lien n'en écoule. L'H.264 viendra avec `ostena-recorder`.
- **Entrées** : les trames clavier, souris et tactiles sont traduites en `Input.dispatchKeyEvent`, `Input.dispatchMouseEvent` et `Input.dispatchTouchEvent`. L'ordonnanceur de l'ADR-0006 garde la priorité des entrées sur les images.
- **Taille** : une demande de changement de taille du portail devient `Emulation.setDeviceMetricsOverride`.

### Droits du grant

Chaque droit est refusé par défaut et appliqué par l'agent :

| Droit (ADR-0004) | Effet |
|---|---|
| presse-papiers vers la cible (bit 0) | collage par `Input.insertText` |
| presse-papiers depuis la cible (bit 1) | non pris en charge dans un premier temps : toujours refusé |
| dépôt de fichiers (bit 2) | sélecteur de fichiers intercepté (`Page.setInterceptFileChooserDialog`) et alimenté par les trames fichier |
| récupération de fichiers (bit 3) | téléchargements autorisés (`Browser.setDownloadBehavior`) dans le `tmpfs`, puis transmis par les trames fichier |
| redirections de lecteurs, imprimante, audio, ports et agent SSH (bits 4 à 8) | sans objet : toujours refusées |

### Navigateur figé et contrôlé

- **Source** : le paquet `chromium` de Debian, installé par le gestionnaire de paquets du client, depuis son miroir local en air gap. Il suit les correctifs de sécurité Debian.
- **Version minimale** : le service refuse de démarrer sous une version minimale fixée dans la configuration, et rapporte la version au core à chaque session. Une version plus ancienne que `agent.web.max_browser_age_days` (60 jours par défaut) déclenche une alerte, sans bloquer.
- **SBOM** : `cargo xtask sbom` ajoute la version de Chromium attendue, hors de l'arbre Cargo.

### Configuration

Nouvelle section `[agent.web]`, désactivée par défaut :

| Clé | Défaut | Rôle |
|---|---|---|
| `enabled` | `false` | active le rôle (refusé sous Windows) |
| `browser_path` | `/usr/bin/chromium` | binaire du navigateur |
| `min_browser_version` | à fixer | version minimale acceptée |
| `max_sessions` | 2 | sessions web simultanées |
| `memory_max_mib` | 1024 | plafond de mémoire par session |
| `cpu_max_percent` | 100 | plafond de CPU par session (100 = un cœur) |
| `allow_jit` | `false` | réactive le JIT JavaScript : **affaiblissement**, journalisé et refusé en mode production |

Les codes de validation (`CFG-V0xx`, `CFG-P0xx`) sont attribués dans la PR de configuration.

### Événements d'audit

| Événement | Contenu |
|---|---|
| `web.session_started` | jti, cible, version du navigateur, limites appliquées |
| `web.navigation` | origine et chemin de chaque navigation de premier niveau, **sans la requête ni le fragment**, qui peuvent porter des jetons |
| `web.connect_denied` | hôte, port et cause (origine non autorisée, ou code `SCP-E0xx`) |
| `web.certificate_denied` | hôte et empreinte SPKI présentée |
| `web.clipboard_to_target` | longueur seulement |
| `web.file_uploaded`, `web.file_downloaded` | nom, taille, SHA-256 |
| `web.transfer_denied` | sens et droit manquant |
| `web.sandbox_failed` | cause (mémoire, plantage, version refusée) |
| `web.session_ended` | raison, durée, mémoire maximale atteinte |

### Hors du champ de cet ADR

- **Injection d'identifiants** dans la console : elle dépend du coffre-fort. Elle fera l'objet d'un ADR à part. Contrainte déjà posée : le secret entre dans le bac à sable de la session, jamais sur le poste d'administration.
- **Enregistrement vidéo** des sessions : avec `ostena-recorder`.
- **Presse-papiers depuis la cible**.
- **Agent Windows**.

### Découpage en PR

1. Cet ADR.
2. Section `[agent.web]` : lecture et validation, tests.
3. Proxy de périmètre dans l'agent, testable sans navigateur, avec sa cible de fuzz.
4. Service `ostena-webiso` et bac à sable (`ostena-platform`), testés sous Debian 12.
5. Client CDP minimal (sur le `serde_json` déjà présent dans le *workspace*), capture d'écran et entrées vers les trames de l'ADR-0006.
6. Droits du grant, transferts et événements d'audit.

## Conséquences

- Le poste d'administration n'exécute jamais de code des cibles web. Une console compromise reste confinée dans un bac à sable jetable, sans accès réseau autre que les origines autorisées, sans état persistant et sans voie vers l'agent.
- Le contrôle de périmètre s'applique à chaque connexion du navigateur, sous-ressources et redirections comprises.
- **Empreinte** : chaque session coûte de l'ordre de quelques centaines de Mio, **à mesurer** au prototype et à publier dans cet ADR. Le plafond `max_sessions` et le cgroup bornent la consommation. Les sessions web relèvent d'un dimensionnement à part de l'agent, et l'empreinte au repos de l'agent ne change pas : le navigateur ne tourne que pendant une session, dans un autre service.
- **Latence** : la capture par images JPEG n'atteindra probablement pas 10 ms ajoutées au p99. **C'est un écart à mesurer et à signaler**, avec deux pistes s'il est confirmé : l'H.264, ou ne renvoyer que les zones modifiées.
- **Établissement** : le lancement de Chromium dans un bac à sable neuf doit tenir dans les 5 s d'établissement. À mesurer également.
- **Sans JIT**, les consoles très lourdes en JavaScript seront plus lentes. Réactiver le JIT reste possible en développement, pas en production.
- **Dépendance extérieure** : la sécurité repose en partie sur un Chromium tenu à jour, que `cargo deny` ne contrôle pas. Le contrôle de version et l'alerte de vieillissement en tiennent lieu. Le client doit intégrer ce paquet à son cycle de correctifs.
- **Second service** : il y a une unité systemd de plus à installer et à durcir, et un groupe partagé entre `ostena` et `ostena-web`.
- **Vérification** :
  - tests unitaires du proxy de périmètre et de la traduction des entrées ;
  - propriétés proptest et cible de fuzz sur l'analyse des requêtes `CONNECT` ;
  - tests d'intégration sous Debian 12 : une page qui tente de joindre une origine non autorisée, une adresse de métadonnées, `file:` ou un port local est bloquée et journalisée ; un certificat non épinglé est refusé ; le `tmpfs` est vide après la session ;
  - bancs d'empreinte par session, de latence entrée → image et de temps d'établissement, affichés en CI.
