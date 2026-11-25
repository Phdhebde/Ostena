# ADR-0016 : Transcripts des sessions

- **Statut** : Accepté, implémenté (jalon M1, PR 8) : format du flux, écrivain asciicast, primitives cryptographiques, capture par l'agent, réception, stockage et scellement par le core, vérification hors ligne.
- **Date** : 2026-11-25

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

L'agent capture les événements et les envoie au fil de la session, sur un flux du tunnel (classe `Recording`, ADR-0008), après l'en-tête de canal de 18 octets. Le flux est une suite de trames, entiers big-endian :

| Taille | Champ |
|---|---|
| 1 | type : 1 début, 2 sortie, 3 taille, 4 fin, 5 fin de commande |
| 8 | temps, en microsecondes depuis le début |
| 4 | longueur de la charge |
| n | charge |

Charges : début `cols u16 ‖ lignes u16 ‖ début en ms Unix u64 ‖ longueur du type de terminal u8 ‖ type ‖ commande présente u8 (0 ou 1) ‖ commande` (jusqu'à la fin de la charge) ; sortie : les octets ; taille `cols u16 ‖ lignes u16` ; fin `raison u8 ‖ octets de sortie u64` ; fin de commande `1 ‖ code u32` (`exit-status`) ou `2 ‖ core u8 (0 ou 1) ‖ nom du signal` (`exit-signal`, 1 à 32 caractères ASCII imprimables, `KILL` et non `SIGKILL`).

**Décodeur strict** (`ostena_recorder::wire::Decoder`), donc `encode(decode(b)) == b` :

- le début vient en premier, au temps 0, une seule fois ; la fin en dernier, avec le nombre exact d'octets de sortie reçus ; rien après ;
- les temps ne reculent jamais ;
- au plus une fin de commande, avant la fin ; l'agent n'enregistre que la première annoncée par la cible, et la consigne avant de la relayer ;
- bornes : sortie de 1 octet à 32 Kio (l'agent découpe au-delà), commande de 32 Kio au plus, type de terminal de 64 caractères ASCII imprimables au plus, 1 à 10 000 colonnes ou lignes (0 et 0 sans terminal), trame de 32 Kio et 91 octets au plus ;
- **limites du core** : taille (256 Mio de sortie par défaut) et durée (8 h 10 min) : `REC-E003` ;
- le décodeur mémorise au plus une trame incomplète.

### Échec fermé (décision du responsable du projet, 2026-11-25)

**Une session dont le transcript ne peut plus être transmis est coupée**, y compris à la coupure du tunnel et au redémarrage du core. Le flux appartient à la connexion QUIC : sa perte coupe aussitôt les sessions SSH de l'agent. Une sortie n'est jamais montrée à l'utilisateur sans avoir été remise à l'enregistreur. Cela rend effective, pour SSH, la coupure à la perte du tunnel que l'ADR-0010 n'avait pas retenue au jalon M1.

Alternative écartée pour M1 : un tampon borné sur l'agent et une reprise du flux après reconnexion. Elle pourra venir plus tard ; le code isole cette décision. Stocker le transcript sur le disque de l'agent est exclu.

Mise en œuvre :

- **agent** (`ostena_ssh::transcript`) : à l'ouverture d'un shell ou d'un `exec`, la trame de début part dans une file bornée (2 trames, 64 Kio de sortie) ; chaque sortie de la cible y entre **avant** d'être relayée à l'utilisateur, et une file pleine fait attendre le relais (contre-pression, pas de perte). Une tâche (`ostena_tunnel::recording::pump`) vide la file sur le flux `Recording`, ouvert avec la session. Si le flux échoue, est arrêté par le core ou perd sa connexion, la file se ferme et la session est coupée : `SSH-E021`, événement `ssh.transcript_lost` (et `agent.transcript_lost` côté service). À la fin normale, l'agent termine le flux et attend l'accusé du core 5 s au plus ;
- **raison de fin** scellée : `closed`, `revoked`, `expired`, `shutdown` ou `error` (transcript perdu).

**Borne réelle de ce qui peut être montré sans être enregistré.** « Remis à l'enregistreur » veut dire entré dans la file de l'agent, pas reçu par le core. Pendant une partition entre l'agent et le core, l'utilisateur peut donc voir, sans que le core le reçoive jamais :

- en volume, au plus la file (2 trames de 32 Kio), la trame que la tâche d'envoi est en train d'écrire (32 Kio) et la fenêtre de réception QUIC du flux accordée par le core (`stream_window`, 256 Kio par défaut), soit **environ 352 Kio** de sortie, en-têtes de trame en plus ;
- en durée, au plus le temps de détecter la partition : la session est coupée quand une trame attend plus de 15 s (`WRITE_TIMEOUT` de l'envoi, `SEND_TIMEOUT` de la file), ou à l'expiration du délai d'inactivité QUIC (15 s par défaut), au premier des deux.

Une session peu bavarde peut ainsi montrer jusqu'à 15 s de sortie non enregistrée, une session très bavarde jusqu'à environ 352 Kio. La fenêtre QUIC ne peut pas être réduite pour le seul flux `Recording` : QUIC (quinn 0.11) n'a qu'une fenêtre de réception par flux pour toute la connexion, et la réduire à 64 Kio limiterait aussi le débit des flux SSH et RDP (64 Kio par aller-retour). Une borne plus serrée demande un crédit applicatif (le core accuse les octets reçus sur le sens retour du flux, l'agent n'en laisse que 64 Kio sans accusé) ; c'est un lot ultérieur.

### Réception et scellement par le core

- Le core n'accepte un flux `Recording` que pour une session SSH **ouverte, de cet agent** (`access_session`) ; sinon, et pour toute autre classe de flux, il arrête le flux (`transcript.refused`, `REC-E002` ; `tunnel.channel_refused`) et l'agent coupe la session.
- Le fichier `<session>.cast` est créé dans `[core.ssh] transcripts_dir` (création exclusive, mode 0600, répertoire 0700). Une ligne `session_transcript` (migration 0005) passe de `recording` à `sealed` ou `incomplete`.
- À la trame de début d'un `exec`, le core consigne `access.ssh_exec` : longueur de la commande et HMAC (ci-dessous), jamais le texte.
- Un flux mal formé, une limite dépassée ou une écriture impossible arrête le flux : le transcript est scellé incomplet avec son code (`REC-E001`, `REC-E003`, `REC-E004`) et la session est coupée par l'agent.
- **Scellement** : à la fin du flux, le fichier est synchronisé sur le disque et passé en lecture seule (0400) ; son SHA-256, sa taille, le nombre d'événements, d'octets de sortie et de séquences UTF-8 invalides, la raison de fin et le code éventuel sont écrits dans la ligne et dans l'enregistrement d'audit `transcript.sealed`, dans une même transaction. Un flux coupé sans trame de fin est scellé incomplet (`REC-E005`).
- **Reprise** : au démarrage, les lignes encore `recording` (core arrêté pendant une session) sont scellées incomplètes, `REC-E005`, sur le contenu présent du fichier ; le journal montre `transcript.recovered`.
- **Pas de SSH sans transcript** : avec `[core.ssh]`, `transcripts_dir` et `command_mac_key` sont obligatoires ; à défaut, la configuration est refusée, et le core refuse de démarrer (`REC-E002`).

### Vérification hors ligne

`ostena audit verify --transcripts <répertoire>` compare chaque transcript scellé dans un export vérifié au fichier du répertoire, sans secret : absent `AUD-E017`, modifié (taille ou SHA-256) `AUD-E018`, fichier `.cast` sans scellé `AUD-W005`, transcript scellé incomplet `AUD-W006`. Seuls les fichiers `.cast` du répertoire sont lus.

### Empreinte de la commande : HMAC-SHA-256 calculé par le core

L'agent ne journalise plus que la longueur d'une commande. Le core, qui reçoit la commande dans le début du transcript, en consigne un **hachage à clé** : HMAC-SHA-256 sous une clé de 256 bits propre au core, à usage unique, par `ostena_crypto::hmac`. Seul celui qui détient la clé vérifie qu'une commande donnée a été lancée ; un auditeur hors ligne lit la commande dans le transcript scellé.

- Message authentifié : `ostena/ssh-exec/v1\0 ‖ identifiant de session (16 octets) ‖ commande` ; la même commande dans deux sessions donne deux empreintes.
- Clé : 32 octets aléatoires, `ostena ca key new-mac --out <fichier>` (mode 0600, jamais écrasé), référencée par `[core.ssh] command_mac_key` comme les autres clés du core (credential systemd ou fichier). Une clé nulle ou de mauvaise taille est refusée au démarrage.
- L'empreinte est dans l'événement `access.ssh_exec` et dans la ligne `session_transcript`.

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

Événements : `access.ssh_exec`, `transcript.sealed`, `transcript.refused` (chaîne d'audit) ; `ssh.transcript_lost`, `agent.transcript_lost`, `transcript.recovered`, `transcript.write_failed`, `tunnel.channel_refused` (journal).

### Crate

Nouvelle crate `ostena-recorder`, prévue dans l'organisation du dépôt : événements, codec du flux, écrivain asciicast. Dépendances : `ostena-crypto` (SHA-256 en flux) et `thiserror`, aucune crate tierce nouvelle. Ni runtime, ni base. Deux cibles `cargo-fuzz` : `recorder_decode` (décodeur, découpage arbitraire du flux, sortie canonique) et `recorder_cast` (décodeur puis écrivain : lignes UTF-8 sans caractère de contrôle, sceau égal au SHA-256 écrit). Leurs corpus sont rejoués en test sur la toolchain stable.

`ostena-crypto` gagne `hmac` (HMAC-SHA-256, clé de 32 octets exactement, ni `Debug` ni `Clone`, vérification en temps constant) et `sha256::Hasher` (SHA-256 incrémental, empreinte d'un préfixe sans s'arrêter).

## Conséquences

- Un transcript se vérifie avec `sha256sum` contre le hachage scellé dans la chaîne d'audit, ou par `ostena audit verify --transcripts`.
- Le répertoire des transcripts grossit sans limite au jalon M1 : sa rétention et son archivage (WORM) relèvent de l'exploitation, puis d'un lot ultérieur.
- L'écriture du fichier se fait dans la tâche de réception, par blocs ; un disque lent ralentit, par contre-pression, la seule session concernée.
- Les transcripts contiennent ce que la session a affiché, secrets compris, et la commande d'un `exec` en clair : ils sont aussi sensibles que la session elle-même.
- Une panne du lien entre l'agent et le core coupe les sessions SSH en cours. C'est le prix de la traçabilité.
- Le décodage UTF-8 avec remplacement perd les octets invalides ; leur nombre est scellé.
