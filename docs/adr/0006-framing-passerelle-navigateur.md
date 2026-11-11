# ADR-0006 : Framing binaire entre la passerelle et le navigateur

- **Statut** : Accepté
- **Date** : 2026-11-11

## Contexte

Le portail web ouvre une session (SSH, RDP, VNC, application web) dans le navigateur. La passerelle et le client web échangent des trames sur une WebSocket chiffrée par TLS : entrées clavier, souris et tactiles dans un sens, mises à jour de l'écran dans l'autre, plus le presse-papiers, les fichiers et l'audit en direct.

Contraintes :
- moins de 20 ms de latence ajoutée, donc **une entrée ne doit jamais attendre une image** ;
- décodage sans copie et sans allocation sur le chemin chaud ;
- un seul code pour la passerelle et pour le navigateur, compilé en WebAssembly (`no_std` + `alloc`) ;
- un format qui permette de reprendre une session après une coupure ;
- aucun secret dans les trames.

## Décision

### En-tête

Tout est en big-endian. **Cet en-tête est figé pour toutes les versions** ; seules les charges utiles évoluent.

| Offset | Taille | Champ |
|---|---|---|
| 0 | 1 | version : 0 pendant la négociation, ensuite la version négociée |
| 1 | 1 | type |
| 2 | 1 | drapeaux : bit 0 `MORE` (un fragment suit), les autres réservés à 0 |
| 3 | 1 | réservé, 0 |
| 4 | 2 | canal |
| 6 | 2 | longueur de la charge utile |
| 8 | 8 | numéro de séquence |

- **Bornes** : chaque type a une longueur maximale. Un en-tête qui annonce plus est refusé dès sa lecture, avant même que la charge utile arrive.
- **Deux modes de décodage** :
  - message : un tampon contient exactement une trame, c'est le cas d'un message WebSocket. Une trame tronquée ou allongée est refusée ;
  - flux : le décodeur rend « incomplet » tant que les octets n'ont pas tous été reçus.

### Types v1

| Code | Type | Sens | Charge maximale |
|---|---|---|---|
| `0x01` | Hello : masque des versions supportées, capacités (0 en v1) | navigateur → passerelle | 8 o |
| `0x02` | HelloAck : version retenue | passerelle → navigateur | 8 o |
| `0x03` | Close : code de raison | les deux | 4 o |
| `0x04` | Error : code (numéro `FRM-E0xx` ou autre) et détail, **sans texte** | les deux | 4 o |
| `0x05`, `0x06` | Ping, Pong : jeton u64 | les deux | 8 o |
| `0x07` | Ack : plus haut numéro de séquence reçu sans trou | les deux | 8 o |
| `0x08` | Resume : plus haut numéro de séquence reçu avant la coupure | les deux | 8 o |
| `0x10` | Clavier : scancode ou keysym, appui ou relâchement, modificateurs | navigateur → passerelle | 8 o |
| `0x11` | Souris : position absolue, boutons, molettes | navigateur → passerelle | 9 o |
| `0x12` | Tactile : identifiant, phase, position, pression | navigateur → passerelle | 9 o |
| `0x20` | Mise à jour d'affichage : codec, rectangle, données (fragmentable) | passerelle → navigateur | 9 o + 16 Kio |
| `0x21` | Taille imposée | passerelle → navigateur | 6 o |
| `0x22` | Demande de changement de taille | navigateur → passerelle | 6 o |
| `0x30` | Presse-papiers : offre de formats | les deux | 4 o |
| `0x31` | Presse-papiers : données (fragmentable) | les deux | 1 o + 16 Kio |
| `0x40` | Fichier : annonce (identifiant, taille, nom) | les deux | 13 o + 255 o |
| `0x41` | Fichier : morceau (identifiant, offset, données) | les deux | 12 o + 16 Kio |
| `0x42` | Fichier : fin (empreinte de 32 octets calculée hors de ce crate) | les deux | 36 o |
| `0x43` | Fichier : annulation | les deux | 6 o |
| `0x50` | Présence d'observateurs et enregistrement en cours | passerelle → navigateur | 4 o |

- **Sens** : chaque type indique les sens où il est permis. Le décodeur refuse un type reçu dans un sens interdit (`FRM-E005`), et l'encodeur refuse de le produire.
- **Canaux** : le contrôle et l'audit sont toujours sur le canal 0.
- **Champs** : tous ont un domaine. Les valeurs inconnues (codec, phase, bouton, format) et les champs réservés non nuls sont refusés. Décoder puis réencoder une trame acceptée redonne exactement les mêmes octets.

**Presse-papiers et fichiers dans les deux sens** : le format permet le presse-papiers et le transfert de fichiers dans les deux sens. **Le filtrage selon les droits du grant (presse-papiers vers ou depuis la cible, dépôt ou récupération de fichiers) relève de la couche session, pas de ce crate.** Le décodeur accepte une trame bien formée ; c'est la session qui décide de la transmettre ou de la refuser, selon les droits portés par le grant.

### Fragmentation

- **16 Kio est un maximum, pas une taille fixe.** La taille des fragments est un paramètre de l'émetteur, par exemple 4 Kio sur un lien lent, sans changement de format ; le décodeur accepte toute taille jusqu'à 16 Kio.
- **Ce que ça garantit** : une entrée n'attend jamais plus qu'un fragment en cours d'envoi. Au pire, environ 13 ms derrière 16 Kio à 10 Mbit/s, et 3 ms avec des fragments de 4 Kio.
- **Mécanique** : chaque fragment répète les métadonnées du message (codec et rectangle, ou format). `MORE` est posé sur tous sauf le dernier.
- **Réassemblage** : il se fait par type et par canal, hors du chemin chaud, avec une taille et un nombre de messages en cours bornés (`FRM-E011`). Les fichiers ne sont pas fragmentés : chaque morceau porte son offset.

### Numéros de séquence et reprise

- **Numérotation** : la séquence est un u64 par sens. **Elle commence à 0** avec la première trame de chaque sens (Hello pour le navigateur, HelloAck pour la passerelle) et augmente de 1 à chaque trame, tous canaux confondus.
- **Ordre** : le numéro est attribué à la sortie de l'ordonnanceur, donc l'ordre sur le réseau est toujours l'ordre des numéros.
- **Contrôle** : le récepteur exige des numéros consécutifs ; un doublon ou un trou est refusé (`FRM-E010`).
- **Acquittement** : Ack permet d'acquitter. L'émetteur conserve ce qui n'a pas été acquitté.
- **Reprise** : après une reconnexion, Resume indique le dernier numéro reçu, et l'émetteur renvoie la suite. Le récepteur reprend alors au numéro attendu. **La reprise elle-même n'est pas implémentée ici**, mais le format la permet sans changement.

### Négociation de version

1. Le navigateur envoie Hello en version 0, avec le masque des versions qu'il supporte (bit `v-1` pour la version `v`).
2. La passerelle retient **la plus haute version commune** et répond HelloAck, ou Error `FRM-E009` (« aucune version commune ») puis Close.
3. Seules Hello et HelloAck utilisent toujours la version 0 ; Error et Close l'acceptent aussi, pour pouvoir refuser une négociation.
4. Toute autre trame avant la négociation est refusée (`FRM-E013`), de même qu'une seconde négociation.

### Ordonnancement

- **Structure** : un `Scheduler` pur, sans runtime. La boucle de session, tokio sur la passerelle ou la boucle d'événements du navigateur, lui confie des trames et les reprend quand le transport peut écrire.
- **Priorité stricte** : contrôle > entrées > audit > données en masse.
- **Données en masse** : affichage, presse-papiers et fichiers se partagent le reste par un tourniquet pondéré par octets (*deficit round robin*), pour qu'un transfert de fichier n'affame pas l'écran.
- **Fusion** : un mouvement de souris en attente est remplacé par le suivant si les boutons n'ont pas changé ; un clic n'est jamais perdu. Une demande de changement de taille en attente est remplacée par la plus récente.
- **Saturation** : une file pleine est refusée (`FRM-E012`) et c'est à l'appelant de décider.

### Aucun secret dans les trames

- **Aucune trame ne porte de secret ni de jeton.** L'authentification a lieu dans la poignée de main WebSocket, avant la première trame. Le crate n'a donc besoin d'aucun type `Secret`, ce qui le laisse `no_std`.
- **Contrat pour la passerelle** (implémentation à venir) :
  - **le grant ne passe JAMAIS dans l'URL de la WebSocket** : les URL se retrouvent dans les journaux des proxys et des serveurs, dans l'historique du navigateur et dans les en-têtes `Referer`. Il passe soit par l'en-tête `Sec-WebSocket-Protocol`, soit par un **cookie `HttpOnly`, `SameSite=Strict`, à usage unique**, posé par le portail juste avant l'ouverture et invalidé dès son premier usage ;
  - **la passerelle vérifie l'en-tête `Origin` contre une liste autorisée** avant d'accepter la WebSocket. C'est la protection contre le détournement de WebSocket entre sites (*cross-site WebSocket hijacking*) : un navigateur envoie les cookies avec une WebSocket ouverte par n'importe quel site ;
  - le futur ticket de reprise suivra les mêmes règles.
- **Données de l'utilisateur** : le clavier, le presse-papiers et les fichiers transportent, par nature, ce que l'utilisateur tape ou copie, mots de passe compris. Leurs types ont un `Debug` qui n'affiche rien (`KeyInput([REDACTED])`) ou seulement la longueur (`Opaque(n octets)`), et pas de `Display`. Il n'existe aucun champ de texte libre : les erreurs sont des codes.
- **Nom de fichier** : c'est le seul champ texte. Il doit être en UTF-8, faire de 1 à 255 octets et ne contenir qu'un seul composant de chemin. Sont refusés :
  - les caractères de contrôle et `< > : " / \ | ? *` ;
  - `.` et `..` ;
  - un point ou une espace final ;
  - les noms réservés de Windows (`CON`, `PRN`, `AUX`, `NUL`, `COM1` à `COM9`, `LPT1` à `LPT9`, et leurs variantes en exposant), avec ou sans extension, quelle que soit la casse.

### Codes

| Code | Refus |
|---|---|
| `FRM-E001` | trame tronquée |
| `FRM-E002` | octets en trop |
| `FRM-E003` | version inconnue, non négociée, ou négociation répétée |
| `FRM-E004` | type inconnu |
| `FRM-E005` | type interdit dans ce sens |
| `FRM-E006` | longueur hors bornes pour le type |
| `FRM-E007` | drapeau inconnu, octet ou champ réservé non nul |
| `FRM-E008` | champ hors domaine (dont le nom de fichier) |
| `FRM-E009` | aucune version commune |
| `FRM-E010` | séquence inattendue (doublon ou trou) |
| `FRM-E011` | fragmentation invalide |
| `FRM-E012` | file d'émission pleine |
| `FRM-E013` | trame reçue avant la négociation |
| `FRM-E014` | canal invalide pour le type |

### Implémentation

- **`ostena-frame`** : `#![no_std]` avec `alloc`, `#![forbid(unsafe_code)]`, **sans aucune dépendance**. `Display` et `core::error::Error` sont écrits à la main.
- **Décodage** : `Frame<'a>` emprunte le tampon et les charges utiles sont lues à des positions fixes. Un test avec `dhat` prouve l'absence d'allocation au décodage et dans le contrôle des séquences.
- **WebAssembly** : la CI construit le crate pour `wasm32-unknown-unknown`.

## Conséquences

- La passerelle et le client web partagent le même code de format : une divergence entre les deux est impossible.
- Faire évoluer le format exige une nouvelle version, négociée. L'en-tête ne change jamais.
- Le contrôle des droits (presse-papiers, fichiers) et la reprise de session restent à écrire dans la couche session.
- **Vérification** :
  - tests unitaires par type et par règle ;
  - propriétés proptest : encoder puis décoder redonne la trame à l'identique ; toute trame tronquée ou allongée est refusée ; un type reçu dans le mauvais sens est refusé ; l'ordonnanceur ne laisse jamais partir une trame d'une classe inférieure tant qu'une trame d'une classe supérieure attend ;
  - deux cibles de fuzz (`frame_decode`, `frame_reassembly`), qui vérifient aussi que décoder puis réencoder redonne les mêmes octets ; leurs corpus sont rejoués sur la toolchain stable ;
  - un banc : environ 26 ns pour décoder une trame d'entrée sur le poste de développement, pour un objectif de 50 ns. Il est affiché en CI sans seuil bloquant, comme pour l'ADR 0005.
