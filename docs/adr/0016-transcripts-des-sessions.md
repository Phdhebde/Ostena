# ADR-0016 : Transcripts des sessions

- **Statut** : Accepté en partie. Le format du flux, l'écrivain asciicast et les primitives cryptographiques sont implémentés (jalon M1, PR 8, première partie). La capture par l'agent, la réception et le stockage par le core, le scellement et la vérification viennent avec la suite de la PR, après les PR 5b et 6.
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

Les sorties de la cible (standard et erreur) et les changements de taille de la fenêtre, avec le type de terminal et la commande d'un `exec`. **Pas les frappes** au jalon M1.

### Format : asciicast v2, écrit par le core

Le fichier stocké est un **asciicast v2**, lisible par les lecteurs courants. Il est écrit par le core, de façon **déterministe** : les mêmes événements donnent les mêmes octets, donc le même SHA-256.

- **En-tête**, clés dans cet ordre : `version` (2), `width`, `height` (80 × 24 sans terminal), `timestamp` (secondes Unix, horloge de l'agent), `command` (un `exec` seulement), `title` (`ostena <session>`), `env` (`TERM`, avec un terminal seulement).
- **Événements** : `[t, "o", texte]` pour une sortie, `[t, "r", "COLSxLIGNES"]` pour un changement de taille ; `t` en secondes, six décimales, depuis le début de la session (horloge monotone de l'agent).
- **UTF-8** : décodé d'un événement à l'autre (une séquence coupée attend la suite). Chaque séquence invalide devient U+FFFD et est **comptée** ; le nombre est scellé avec le transcript. C'est une perte assumée : un terminal affiche de toute façon U+FFFD.
- **Échappement** : aucun caractère de contrôle dans le fichier hors des fins de ligne. C0, DEL et C1 sont écrits `\uXXXX`, séquences d'échappement de la session comprises : afficher le fichier dans un terminal ne l'altère pas. Un lecteur asciicast rejoue la session.

Alternative écartée : un format binaire exact dont l'asciicast serait dérivé. Il garde les octets invalides, mais double les formats et sépare ce qui est scellé de ce qui est lu.

### Flux de l'agent vers le core

L'agent capture les événements et les envoie au fil de la session, sur un flux du tunnel (classe `Recording`, ADR-0008), après l'en-tête de canal de 18 octets. Le flux est une suite de trames, entiers big-endian :

| Taille | Champ |
|---|---|
| 1 | type : 1 début, 2 sortie, 3 taille, 4 fin |
| 8 | temps, en microsecondes depuis le début |
| 4 | longueur de la charge |
| n | charge |

Charges : début `cols u16 ‖ lignes u16 ‖ début en ms Unix u64 ‖ longueur du type de terminal u8 ‖ type ‖ commande présente u8 (0 ou 1) ‖ commande` (jusqu'à la fin de la charge) ; sortie : les octets ; taille `cols u16 ‖ lignes u16` ; fin `raison u8 ‖ octets de sortie u64`.

**Décodeur strict** (`ostena_recorder::wire::Decoder`), donc `encode(decode(b)) == b` :

- le début vient en premier, au temps 0, une seule fois ; la fin en dernier, avec le nombre exact d'octets de sortie reçus ; rien après ;
- les temps ne reculent jamais ;
- bornes : sortie de 1 octet à 32 Kio (l'agent découpe au-delà), commande de 32 Kio au plus, type de terminal de 64 caractères ASCII imprimables au plus, 1 à 10 000 colonnes ou lignes (0 et 0 sans terminal), trame de 32 Kio et 91 octets au plus ;
- **limites du core** : taille (256 Mio de sortie par défaut) et durée (8 h 10 min) : `REC-E003` ;
- le décodeur mémorise au plus une trame incomplète.

### Échec fermé (décision du responsable du projet, 2026-11-25)

**Une session dont le transcript ne peut plus être transmis est coupée**, y compris à la coupure du tunnel et au redémarrage du core. Le flux appartient à la connexion QUIC : sa perte coupe aussitôt les sessions SSH de l'agent. Une sortie n'est jamais montrée à l'utilisateur sans avoir été remise à l'enregistreur. Cela rend effective, pour SSH, la coupure à la perte du tunnel que l'ADR-0010 n'avait pas retenue au jalon M1.

Alternative écartée pour M1 : un tampon borné sur l'agent et une reprise du flux après reconnexion. Elle pourra venir plus tard ; le code isole cette décision. Stocker le transcript sur le disque de l'agent est exclu.

### Empreinte de la commande : HMAC-SHA-256 calculé par le core

L'agent ne journalise plus que la longueur d'une commande. Le core, qui reçoit la commande dans le début du transcript, en consigne un **hachage à clé** : HMAC-SHA-256 sous une clé de 256 bits propre au core, à usage unique, par `ostena_crypto::hmac`. Seul celui qui détient la clé vérifie qu'une commande donnée a été lancée ; un auditeur hors ligne lit la commande dans le transcript scellé.

### Codes

| Code | Signification |
|---|---|
| `REC-E001` | flux de transcript mal formé (trame, ordre) |
| `REC-E002` | réservé : session sans transcript possible (core) |
| `REC-E003` | taille ou durée maximale dépassée |
| `REC-E004` | écriture du transcript impossible |
| `REC-E005` | transcript incomplet : flux terminé sans trame de fin ou au milieu d'une trame |

### Crate

Nouvelle crate `ostena-recorder`, prévue dans l'organisation du dépôt : événements, codec du flux, écrivain asciicast. Dépendances : `ostena-crypto` (SHA-256 en flux) et `thiserror`, aucune crate tierce nouvelle. Ni runtime, ni base. Deux cibles `cargo-fuzz` : `recorder_decode` (décodeur, découpage arbitraire du flux, sortie canonique) et `recorder_cast` (décodeur puis écrivain : lignes UTF-8 sans caractère de contrôle, sceau égal au SHA-256 écrit). Leurs corpus sont rejoués en test sur la toolchain stable.

`ostena-crypto` gagne `hmac` (HMAC-SHA-256, clé de 32 octets exactement, ni `Debug` ni `Clone`, vérification en temps constant) et `sha256::Hasher` (SHA-256 incrémental, empreinte d'un préfixe sans s'arrêter).

## Conséquences

- Un transcript se vérifie avec `sha256sum` contre le hachage scellé dans la chaîne d'audit ; le vérificateur le fera de lui-même (suite de la PR).
- Les transcripts contiennent ce que la session a affiché, secrets compris, et la commande d'un `exec` en clair : ils sont aussi sensibles que la session elle-même.
- Une panne du lien entre l'agent et le core coupe les sessions SSH en cours. C'est le prix de la traçabilité.
- Le décodage UTF-8 avec remplacement perd les octets invalides ; leur nombre est scellé.
