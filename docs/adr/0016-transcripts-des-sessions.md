# ADR-0016 : Transcripts des sessions

- **Statut** : Accepté, implémenté (jalon M1, PR 8) : format du flux, écrivain asciicast, primitives cryptographiques, capture par l'agent, réception, stockage et scellement par le core, vérification hors ligne.
- **Date** : 2026-11-25
- **Révision** : 2026-11-26, jalon M2 (PR 2c) : grâce de reconnexion. Accusés applicatifs du core, tampon borné sur l'agent, reprise du flux sur la nouvelle connexion, scellement différé ; l'échec fermé est gardé au-delà de la grâce ou du tampon.
- **Révision** : 2026-11-25, relecture de sécurité : session coupée quand le core ne lit plus, écriture hors des workers async, limite des refus de flux, `AUD-E019`, `AUD-E020`, `AUD-W007`, `AUD-W008`, `CFG-P016`, empreinte de la commande dans le sceau avec l'identifiant de sa clé, fin de commande enregistrée, caractères bidirectionnels échappés, borne de ce qui peut être montré sans être enregistré

## Contexte

La traçabilité forte est une exigence première du bastion : un auditeur doit pouvoir revoir ce qu'une session a montré, et prouver que la trace n'a pas été retouchée. L'ADR-0010 prévoit que le driver SSH écrive un transcript et le transmette au core ; l'ADR-0012 fournit la chaîne d'audit et son vérificateur hors ligne.

Contraintes :

- **l'agent ne détient rien** : aucune base, aucune trace durable ;
- le core reçoit le transcript d'un agent, entrée non fiable : décodeur strict, borné, *fuzzable* ;
- la trace doit se vérifier hors ligne, sans secret ;
- une ligne de commande peut contenir un secret : son empreinte simple (`ssh.exec`, ADR-0010) se retrouve par dictionnaire.

## Décision

### Ce qui est enregistré

Les sorties de la cible (standard et erreur) et les changements de taille de la fenêtre, avec le type de terminal et la commande d'un `exec`, et la fin du shell ou de la commande telle que la cible l'annonce (`exit-status` ou `exit-signal`). **Pas les frappes** au jalon M1.

### Format : asciicast v2, écrit par le core

Le fichier stocké est un **asciicast v2**, lisible par les lecteurs courants. Il est écrit par le core, de façon **déterministe** : les mêmes événements donnent les mêmes octets, donc le même SHA-256.

- **En-tête**, clés dans cet ordre : `version` (2), `width`, `height` (80 × 24 sans terminal), `timestamp` (secondes Unix, horloge de l'agent), `command` (un `exec` seulement), `title` (`ostena <session>`), `env` (`TERM`, avec un terminal seulement).
- **Événements** : `[t, "o", texte]` pour une sortie, `[t, "r", "COLSxLIGNES"]` pour un changement de taille, un marqueur `[t, "m", "exit-status N"]` ou `[t, "m", "exit-signal NOM"]` (suivi de ` core-dumped` si la cible l'indique) pour la fin du shell ou de la commande ; `t` en secondes, six décimales, depuis le début de la session (horloge monotone de l'agent).
- **UTF-8** : décodé d'un événement à l'autre (une séquence coupée attend la suite). Chaque séquence invalide devient U+FFFD et est **comptée** ; le nombre est scellé avec le transcript. C'est une perte assumée : un terminal affiche de toute façon U+FFFD.
- **Échappement** : aucun caractère de contrôle dans le fichier hors des fins de ligne. C0, DEL et C1 sont écrits `\uXXXX`, séquences d'échappement de la session comprises : afficher le fichier dans un terminal ne l'altère pas. Les caractères de format bidirectionnels (U+061C, U+200E, U+200F, U+202A à U+202E, U+2066 à U+2069) sont échappés de même, dans la commande comme dans les sorties : ils pourraient faire lire une commande pour une autre. Un lecteur asciicast rejoue la session.
- **Risque du rejeu** : un lecteur qui rejoue le transcript dans un vrai terminal y exécute les séquences d'échappement de la session, comme la session l'a fait (titre de fenêtre, presse-papiers, voire réponses injectées par certains émulateurs). Un transcript se rejoue dans un lecteur isolé (navigateur, terminal jetable), pas dans le terminal d'un administrateur.

Alternative écartée : un format binaire exact dont l'asciicast serait dérivé. Il garde les octets invalides, mais double les formats et sépare ce qui est scellé de ce qui est lu.

### Flux de l'agent vers le core

L'agent capture les événements et les envoie au fil de la session, sur un flux du tunnel (classe `Recording`, ADR-0008), après l'en-tête de canal de 18 octets et un **préambule** de 4 octets : `type u8 ‖ 0 u8 ‖ grâce en secondes u16`. Le type vaut 1 pour un nouveau transcript, qui annonce la grâce de l'agent (300 s au plus, une valeur plus grande est ramenée à 300), et 2 pour la reprise d'un transcript déjà commencé (grâce à 0). Le flux est ensuite une suite de trames, entiers big-endian :

| Taille | Champ |
|---|---|
| 1 | type : 1 début, 2 sortie, 3 taille, 4 fin, 5 fin de commande |
| 8 | temps, en microsecondes depuis le début |
| 4 | longueur de la charge |
| n | charge |

Charges : début `cols u16 ‖ lignes u16 ‖ début en ms Unix u64 ‖ longueur du type de terminal u8 ‖ type ‖ commande présente u8 (0 ou 1) ‖ commande` (jusqu'à la fin de la charge) ; sortie : les octets ; taille `cols u16 ‖ lignes u16` ; fin `raison u8 ‖ octets de sortie u64` ; fin de commande `1 ‖ code u32` (`exit-status`) ou `2 ‖ core u8 (0 ou 1) ‖ nom du signal` (`exit-signal`, 1 à 32 caractères ASCII imprimables, `KILL` et non `SIGKILL`).

**Sens retour : accusés du core.** Le core répond sur le même flux par des entiers de 8 octets big-endian : le nombre cumulé d'octets de transcript (comptés après le préambule, d'un flux à l'autre) qu'il a écrits dans le fichier, c'est-à-dire remis au noyau ; le dernier accusé suit la synchronisation finale sur le disque. Sur un flux de reprise, le premier entier est l'offset de reprise : les octets que le core a reçus, trame partielle comprise (il garde l'état de son décodeur). Un accusé qui recule ou qui dépasse ce que l'agent a envoyé est une violation : la session est coupée.

**Décodeur strict** (`ostena_recorder::wire::Decoder`), donc `encode(decode(b)) == b` :

- le début vient en premier, au temps 0, une seule fois ; la fin en dernier, avec le nombre exact d'octets de sortie reçus ; rien après ;
- les temps ne reculent jamais ;
- au plus une fin de commande, avant la fin ; l'agent n'enregistre que la première annoncée par la cible, et la consigne avant de la relayer ;
- bornes : sortie de 1 octet à 32 Kio (l'agent découpe au-delà), commande de 32 Kio au plus, type de terminal de 64 caractères ASCII imprimables au plus, 1 à 10 000 colonnes ou lignes (0 et 0 sans terminal), trame de 32 Kio et 91 octets au plus ;
- **limites du core** : taille (256 Mio de sortie par défaut) et durée (8 h 10 min) : `REC-E003` ;
- le décodeur mémorise au plus une trame incomplète.

### Échec fermé (décision du responsable du projet, 2026-11-25), avec une grâce bornée

**Une session dont le transcript ne peut plus être transmis est coupée.** Une sortie n'est jamais montrée à l'utilisateur sans avoir été remise à l'agent pour l'envoi, et aucune donnée d'enregistrement n'est perdue en silence : ce que le core n'a pas accusé est soit envoyé plus tard, soit compté dans l'erreur qui coupe la session, et le core scelle alors le transcript incomplet.

Au jalon M1, la perte du flux coupait aussitôt les sessions, y compris à la coupure du tunnel. Le jalon M2 ajoute une **grâce de reconnexion** : pendant une coupure plus courte que la grâce, la session continue et son transcript est gardé sur l'agent, en mémoire, jusqu'à sa reprise. Stocker le transcript sur le disque de l'agent reste exclu.

Mise en œuvre :

- **agent** (`ostena_ssh::transcript`) : à l'ouverture d'un shell ou d'un `exec`, la trame de début part dans une file bornée (2 trames, 64 Kio de sortie). Chaque sortie de la cible y entre **avant** d'être relayée à l'utilisateur, et une file pleine fait attendre le relais (contre-pression, pas de perte). Une attente de plus de 15 s (`SEND_TIMEOUT`) coupe la session.
- **tampon et accusés** (`ostena_tunnel::recording`) : la tâche d'envoi vide la file dans un **tampon de 1 Mio** (`BUFFER`) qu'elle écrit sur le flux `Recording`. Chaque octet y reste jusqu'à l'accusé du core. Connecté, un tampon plein fait attendre la file (contre-pression). Si le core, connecté, n'accuse rien pendant 15 s (`WRITE_TIMEOUT`), l'agent réinitialise le flux (code 2) et le traite comme une coupure.
- **grâce** : `[agent.ssh] reconnect_grace_secs`, 60 s par défaut, de 0 à 300 ; 0 rend le comportement du jalon M1. Quand le flux est perdu avec sa connexion, la session continue et les sorties s'accumulent dans le tampon. L'agent attend que le lien revienne : il retente alors toutes les 2 s au plus (`URGENT_RETRY`), au lieu du délai exponentiel qui peut monter à 60 s. Il ouvre ensuite un flux de reprise et renvoie le tampon à partir de l'offset que le core a reçu. La grâce court depuis le moment où l'agent constate la perte (délai d'inactivité du tunnel, 15 s par défaut). Le renouvellement du certificat, qui rouvre la connexion, profite de la même reprise.
- **coupure de la session** (`SSH-E021`, `ssh.transcript_lost`, `agent.transcript_lost`), dans chacun de ces cas :
  - la grâce est dépassée ;
  - le tampon est plein pendant la coupure ;
  - le core refuse le flux ou la reprise (flux arrêté ou terminé par le core) ;
  - un accusé est invalide.

  L'erreur dit combien d'octets le core n'a jamais accusés.
- **fin normale** : l'agent termine le flux et attend 5 s au plus que le core accuse tous les octets, synchronisés sur le disque. Cela ne dit **pas** que le core les a scellés : le sceau se lit dans la chaîne d'audit (`transcript.sealed`).
- **gestionnaire SSH** : il n'attend jamais le core. Un changement de taille est gardé et enregistré avant la sortie suivante. La fin du transcript est attendue 40 s au plus ; le permis de session et le bilan sont toujours rendus. Le bilan (`session_closed`) attend lui aussi le retour du lien pendant la grâce.
- **ouverture interrompue** : si l'agent ne peut pas commencer une session que le core a ouverte (compte ou clé d'hôte de la cible différents, flux `Recording` impossible à ouvrir), il envoie aussitôt son bilan (`session_closed`, raison « ouverture interrompue »).
- **raison de fin** scellée : `closed`, `revoked`, `expired`, `shutdown` ou `error` (transcript perdu).

**Borne de ce qui peut être montré sans être écrit par le core** : le tampon de l'agent (1 Mio), plus la file (2 trames de 32 Kio). La fenêtre de réception du transport ne compte plus, puisque l'agent ne libère un octet que sur l'accusé applicatif. En durée, c'est la grâce, plus le temps de constater la coupure. Ces octets ne sont jamais perdus en silence : ils sont écrits après la reprise, ou la session est coupée, le nombre d'octets perdus journalisé et le transcript scellé incomplet. Cela remplace la borne du jalon M1 (environ 352 Kio ou 15 s, sans compte de ce qui était perdu).

### Réception et scellement par le core

- Le core n'accepte un flux `Recording` que pour une session SSH **ouverte, de cet agent** (`access_session`) ; sinon, et pour toute autre classe de flux, il arrête le flux (`transcript.refused`, `REC-E002` ; `tunnel.channel_refused`) et l'agent coupe la session. `transcript.refused` est de classe protectrice (ADR-0012). Les refus sont limités par agent (8 d'affilée, puis un toutes les 15 s, `rate::Limiter`) : au-delà, le tunnel de l'agent est fermé et un seul journal agrégé `tunnel.streams_limited` remplace un événement par refus.
- Le fichier `<session>.cast` est créé dans `[core.ssh] transcripts_dir` (création exclusive, mode 0600, répertoire 0700), puis le répertoire est synchronisé sur le disque. Une ligne `session_transcript` (migration 0005) passe de `recording` à `sealed` ou `incomplete`. Au démarrage, ce répertoire doit appartenir à root ou au compte du service, sans aucun droit pour le groupe ni les autres ; tant qu'il n'existe pas, son parent ne doit être modifiable par personne d'autre (`CFG-P016`, refusé en production).
- **Accusés** : l'écrivain publie, après chaque vidage de son tampon dans le fichier, l'offset de la dernière trame complète écrite ; la lecture l'envoie à l'agent. Le dernier accusé part après la synchronisation finale et le passage en lecture seule, avant le scellement.
- **Scellement différé pendant la grâce** : si le flux est perdu avec sa connexion, ou réinitialisé par l'agent faute d'accusé (code 2), le core ne scelle pas. Il garde le décodeur, le fichier ouvert et les compteurs, et attend un flux de reprise pendant la grâce annoncée par l'agent plus 30 s (`RESUME_MARGIN`). Cette marge couvre l'écart entre l'instant où le core et celui où l'agent constatent la coupure. Un flux de reprise n'est accepté que pour un transcript en cours d'enregistrement par ce core et venant du même agent ; sinon il est refusé (`REC-E002`, `transcript.refused`) et l'agent coupe la session. Un flux de reprise qui arrive alors que l'ancien semble encore vivant le remplace (l'ancien est arrêté, code 3). Passé le délai, le transcript est scellé incomplet (`REC-E005`), comme avant. Événements : `transcript.interrupted`, `transcript.resumed` (journal).
- **Écriture hors des workers async** : la lecture du flux QUIC reste asynchrone ; les trames passent par une file bornée (16 trames) à un écrivain dédié (`spawn_blocking`), qui écrit le fichier, le synchronise et le scelle. Un disque lent ne bloque aucun worker du runtime.
- À la trame de début d'un `exec`, le core consigne `access.ssh_exec` : longueur de la commande et HMAC (ci-dessous), jamais le texte.
- Un flux mal formé, une limite dépassée ou une écriture impossible arrête le flux : le transcript est scellé incomplet avec son code (`REC-E001`, `REC-E003`, `REC-E004`) et la session est coupée par l'agent.
- **Sceau d'un fichier après une erreur d'écriture** : le core mesure le fichier réel sur le disque (taille, SHA-256) et scelle cette mesure, jamais ce qu'il croyait avoir écrit ; un fichier absent est scellé sans empreinte ni taille. Si la mesure elle-même échoue, rien n'est scellé : la ligne reste `recording` (`transcript.seal_failed`, niveau erreur) et la reprise du démarrage suivant la scelle.
- **Scellement** : à la fin du flux, le fichier est synchronisé sur le disque et passé en lecture seule (0400) ; son SHA-256, sa taille, le nombre d'événements, d'octets de sortie et de séquences UTF-8 invalides, la raison de fin et le code éventuel sont écrits dans la ligne et dans l'enregistrement d'audit `transcript.sealed`, dans une même transaction. Un flux coupé sans trame de fin est scellé incomplet (`REC-E005`).
- **Reprise** : au démarrage, les lignes encore `recording` (core arrêté pendant une session) sont scellées incomplètes, `REC-E005`, sur le contenu présent du fichier ; le journal montre `transcript.recovered`.
- **Pas de SSH sans transcript** : avec `[core.ssh]`, `transcripts_dir` et `command_mac_key` sont obligatoires ; à défaut, la configuration est refusée, et le core refuse de démarrer (`REC-E002`).

### Vérification hors ligne

`ostena audit verify --transcripts <répertoire>` compare chaque transcript scellé dans un export vérifié au fichier du répertoire, sans secret : absent `AUD-E017`, modifié (taille ou SHA-256) `AUD-E018`, fichier `.cast` sans scellé `AUD-W005`, transcript scellé incomplet `AUD-W006`. Seuls les fichiers `.cast` du répertoire sont lus.

Le vérificateur contrôle aussi les sceaux eux-mêmes et leur couverture :

- un `transcript.sealed` aux champs absents ou mal formés, ou un second sceau pour la même session, est une erreur (`AUD-E020`), avec ou sans `--transcripts` ;
- avec `--transcripts`, toute `access.session_opened` SSH de l'export sans `transcript.sealed` est une erreur (`AUD-E019`) dès que la session aurait dû finir (ouverture plus durée maximale plus 5 min, avant l'instant de l'export) ; avant, c'est un avertissement (`AUD-W007`, session peut-être encore ouverte) ;
- avec `--transcripts`, un sceau postérieur à la dernière tête signée donne un avertissement pour son transcript (`AUD-W008`) : l'enregistrement pourrait encore être changé avec son fichier.

### Empreinte de la commande : HMAC-SHA-256 calculé par le core

L'agent ne journalise plus que la longueur d'une commande. Le core, qui reçoit la commande dans le début du transcript, en consigne un **hachage à clé** : HMAC-SHA-256 sous une clé de 256 bits propre au core, à usage unique, par `ostena_crypto::hmac`. Seul celui qui détient la clé vérifie qu'une commande donnée a été lancée ; un auditeur hors ligne lit la commande dans le transcript scellé.

- Message authentifié : `ostena/ssh-exec/v1\0 ‖ identifiant de session (16 octets) ‖ commande` ; la même commande dans deux sessions donne deux empreintes.
- Clé : 32 octets aléatoires, `ostena ca key new-mac --out <fichier>` (mode 0600, jamais écrasé), référencée par `[core.ssh] command_mac_key` comme les autres clés du core (credential systemd ou fichier). Une clé nulle ou de mauvaise taille est refusée au démarrage.
- L'empreinte est dans l'événement `access.ssh_exec`, dans la ligne `session_transcript` et dans le sceau `transcript.sealed`, avec sa longueur et l'**identifiant de la clé** (`kid`) : les 16 premiers chiffres hexadécimaux de `HMAC(clé, "ostena/ssh-exec/key-id/v1\0")`. Il désigne la clé sans la révéler : après une rotation, on sait sous quelle clé recalculer une empreinte.

### Codes

| Code | Signification |
|---|---|
| `REC-E001` | flux de transcript mal formé (trame, ordre) |
| `REC-E002` | transcript refusé par le core (session inconnue, close ou d'un autre agent, flux d'une autre classe), ou `[core.ssh]` sans transcripts |
| `REC-E003` | taille ou durée maximale dépassée |
| `REC-E004` | écriture du transcript impossible |
| `REC-E005` | transcript incomplet : flux terminé sans trame de fin ou au milieu d'une trame, ou interrompu par l'arrêt du core |
| `SSH-E021` | session coupée par l'agent : transcript perdu |
| `AUD-E017` | transcript scellé absent du répertoire vérifié |
| `AUD-E018` | transcript modifié depuis son scellement |
| `AUD-W005` | fichier de transcript sans scellé dans l'export |
| `AUD-W006` | transcript scellé incomplet |
| `AUD-E019` | session SSH ouverte dans l'export sans transcript scellé |
| `AUD-E020` | sceau de transcript mal formé, ou second sceau pour la même session |
| `AUD-W007` | session SSH sans transcript scellé, peut-être encore ouverte |
| `AUD-W008` | sceau de transcript non couvert par une tête signée |
| `CFG-P016` | répertoire des transcripts accessible au-delà du compte du service, ou parent modifiable par un autre compte |

Événements : `access.ssh_exec`, `transcript.sealed`, `transcript.refused` (chaîne d'audit) ; `ssh.transcript_lost`, `agent.transcript_lost`, `agent.transcript_interrupted`, `agent.transcript_resumed`, `transcript.interrupted`, `transcript.resumed`, `transcript.recovered`, `transcript.write_failed`, `transcript.seal_failed`, `tunnel.channel_refused`, `tunnel.streams_limited` (journal).

### Crate

Nouvelle crate `ostena-recorder`, prévue dans l'organisation du dépôt : événements, codec du flux, écrivain asciicast. Dépendances : `ostena-crypto` (SHA-256 en flux) et `thiserror`, aucune crate tierce nouvelle. Ni runtime, ni base. Deux cibles `cargo-fuzz` : `recorder_decode` (décodeur, découpage arbitraire du flux, sortie canonique) et `recorder_cast` (décodeur puis écrivain : lignes UTF-8 sans caractère de contrôle, sceau égal au SHA-256 écrit). Leurs corpus sont rejoués en test sur la toolchain stable.

`ostena-crypto` gagne `hmac` (HMAC-SHA-256, clé de 32 octets exactement, ni `Debug` ni `Clone`, vérification en temps constant) et `sha256::Hasher` (SHA-256 incrémental, empreinte d'un préfixe sans s'arrêter).

## Conséquences

- Un transcript se vérifie avec `sha256sum` contre le hachage scellé dans la chaîne d'audit, ou par `ostena audit verify --transcripts`.
- Le répertoire des transcripts grossit sans limite au jalon M1 : sa rétention et son archivage (WORM) relèvent de l'exploitation, puis d'un lot ultérieur.
- L'écriture du fichier se fait dans un écrivain dédié, par blocs ; un disque lent ralentit, par contre-pression, la seule session concernée, que l'agent coupe au bout de 15 s d'attente.
- Les transcripts contiennent ce que la session a affiché, secrets compris, et la commande d'un `exec` en clair : ils sont aussi sensibles que la session elle-même.
- Une panne du lien entre l'agent et le core plus longue que la grâce (60 s par défaut), ou pendant laquelle une session affiche plus d'1 Mio, coupe les sessions SSH en cours. C'est le prix de la traçabilité.
- **Pendant la grâce, le core ne peut plus rien imposer à la session** : une révocation (session de connexion, agent) ne lui parvient qu'à la reconnexion, où le core la répète. La durée maximale de la session reste appliquée par l'agent. La grâce allonge donc d'autant le délai d'effet d'une révocation ; elle est bornée à 300 s, et 0 rend la coupure immédiate.
- L'agent garde jusqu'à 1 Mio par session SSH (64 sessions par défaut, soit 64 Mio au pire), seulement pendant une coupure ou quand le core accuse lentement.
- Le décodage UTF-8 avec remplacement perd les octets invalides ; leur nombre est scellé.

### Limites connues

- Pendant une coupure, l'utilisateur peut voir jusqu'à 1 Mio de sortie (le tampon), ou la durée de la grâce, que le core n'écrira jamais si le lien ne revient pas à temps. Ce n'est jamais silencieux : la session est alors coupée, le nombre d'octets perdus journalisé, le transcript scellé incomplet.
- Un redémarrage du core pendant la grâce coupe les sessions : au démarrage, le core scelle incomplets les transcripts restés ouverts et refuse leur reprise. Une coupure avant que le premier octet du transcript ait atteint le core coupe aussi la session : la reprise d'un transcript inconnu est refusée.
- Une session ouverte par le core mais que l'agent n'a pas pu commencer (ouverture interrompue) n'a pas de transcript : la vérification avec `--transcripts` la signale `AUD-E019`. Le bilan de l'agent la ferme, mais aucun sceau « sans transcript » n'est écrit au jalon M1.
- `AUD-W007` repose sur la durée maximale de la session plus une marge de 5 min, comparée à l'instant de l'export : une horloge du core décalée de plus de 5 min peut faire passer une session finie pour ouverte, ou l'inverse.
- Un transcript repris au démarrage (`REC-E005`) est scellé sur le contenu du fichier, avec des compteurs d'événements et de séquences UTF-8 invalides à 0 : ils ne sont pas recalculés.
- Une fin de commande est enregistrée telle que la cible l'annonce : une cible compromise peut mentir sur son code de sortie.
- La durée d'une session repose sur l'horloge de l'agent : le core n'impose pas de délai propre à un flux muet, qui reste ouvert tant que la liaison vit.
- Le core est mono-instance au jalon M1 : au démarrage, il scelle incomplets tous les transcripts restés ouverts. Plusieurs instances partageant la base demanderont de ne reprendre que ceux de l'instance.
- Chaque sortie de la cible est copiée trois fois sur l'agent avant l'envoi, et le tampon de ligne du core garde sa capacité maximale (environ 200 Kio par flux). À réduire si les bancs ou l'empreinte le demandent.
