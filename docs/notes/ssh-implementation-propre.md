# Note : implémentation SSH propre (option B)

- **Statut** : chantier à reprendre après le jalon M1. Pas encore d'ADR.
- **Date** : 2026-11-13
- **Origine** : écart SSH de l'[ADR-0009](../adr/0009-choix-cryptographiques.md), accès SSH natif de l'[ADR-0010](../adr/0010-acces-ssh-natif.md).

## Pourquoi

Pour M1, l'accès SSH s'appuie sur russh 0.65.1. Cela a un coût :

- **Une exception cryptographique** : ECDH et ECDSA passent par RustCrypto, l'aléa par `rand`.
- **Des dépendances lourdes** : environ 90 crates de plus, dont `ssh-key` en version préliminaire, et beaucoup d'algorithmes inutiles à la liste figée.
- **Un strict KEX impossible à exiger** : il a fallu un pré-contrôle avant la bibliothèque.

Une implémentation propre, limitée à la liste figée et entièrement sur `ostena-crypto`, supprimerait l'exception et presque toutes ces dépendances.

## Périmètre minimal

Serveur (agent, face aux clients OpenSSH) et client (driver, face aux cibles OpenSSH), avec un seul jeu d'algorithmes.

| Couche | Contenu | Hors périmètre |
|---|---|---|
| Transport (RFC 4253) | identification ; paquets ; `KEXINIT` à liste unique ; `ecdh-sha2-nistp256` (RFC 5656) par `ostena-crypto` ; dérivation des clés ; `aes256-gcm@openssh.com` (RFC 5647, variante OpenSSH) ; **strict KEX natif** ; renégociation par volume et durée ; `SSH_MSG_IGNORE`, `DEBUG`, `DISCONNECT`, `UNIMPLEMENTED` | tout autre algorithme, compression |
| Authentification (RFC 4252) | `publickey` avec `ecdsa-sha2-nistp256` et certificats OpenSSH `-cert-v01` (format `PROTOCOL.certkeys`), côté serveur (vérification par la CA) et côté client (clé de l'agent) | mot de passe, keyboard-interactive, GSSAPI |
| Connexion (RFC 4254) | canaux `session` ; fenêtres et contrôle de flux ; `pty-req`, `shell`, `exec`, `window-change`, `env` (liste blanche), `exit-status`, `exit-signal`, `eof`, `close` ; keepalive | redirections, X11, agent forwarding, SFTP (lot ultérieur) |
| Hôte | vérification stricte de la clé hôte de la cible (empreinte de l'inventaire) ; certificat d'hôte de l'agent | `known_hosts` |

**Exigences** :
- un analyseur par message, borné, testé par propriétés et fuzzé ;
- des vecteurs de test RFC pour la dérivation des clés et GCM ;
- interopérabilité avec OpenSSH 8.9 à 9.x et PuTTY récent (client), et OpenSSH de Debian 12 et RHEL 9 (cible).

## Estimation

| Tâche | Charge |
|---|---|
| Transport et échange de clés, avec tests et fuzz | 1,5 semaine |
| Authentification et certificats | 1 semaine |
| Canaux et requêtes de session | 1 semaine |
| Client (réutilise l'essentiel) | 0,5 semaine |
| Interopérabilité, durcissement, documentation | 1 semaine |

Total : **4 à 5 semaines**. À ajouter : l'impact sur la cible de sécurité CSPN, qui gagne en simplicité (une seule implémentation de P-256, plus de version préliminaire).

## Critères de décision

À reprendre après M1, ou plus tôt si l'un des critères de réexamen de l'ADR-0009 se déclenche (`ssh-key` 0.7 stable, avis RustSec, fin de M1). Alternative à évaluer au même moment : une contribution amont pour que russh fasse passer ECDH et ECDSA par `aws-lc-rs`.
