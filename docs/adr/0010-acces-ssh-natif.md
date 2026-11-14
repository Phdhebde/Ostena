# ADR-0010 : Accès SSH natif

- **Statut** : Accepté en partie. Le parcours, les clés de l'agent sur les cibles, la liste d'algorithmes et le pré-contrôle sont décidés. Ce dernier est implémenté avec la configuration de la bibliothèque (lot M1, PR 1). Le serveur SSH de l'agent, le driver client et les certificats viendront dans les PR suivantes du jalon M1.
- **Date** : 2026-11-13

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

L'analyseur est testé par propriétés et par une cible `cargo-fuzz` (`ssh_precheck`), dont le corpus part d'offres réelles capturées d'OpenSSH 9.5 (client) et 9.2 (serveur Debian 12).

### Défaut amont : clés P-256 à scalaire court

`ssh-key 0.7.0-rc.11`, imposée par russh, refuse une clé privée P-256 dont OpenSSH encode le scalaire sur **31 octets**, quand il commence par un octet nul : `Encoding(Length)`. Cela concerne environ une clé sur 256 produite par `ssh-keygen`. Constaté sur 600 clés générées (une refusée), et vérifié par décodage de la clé fautive. Les clés à 32 ou 33 octets passent.

- **L'agent génère et stocke lui-même ses clés** (clé hôte, clé pour les cibles), par `ostena-crypto`, avec un scalaire de 32 octets fixes. Il ne charge pas de clé produite par `ssh-keygen`.
- Les tests et les scripts qui passent par `ssh-keygen` régénèrent une clé que russh ne sait pas lire.
- À signaler en amont, et à revérifier avec `ssh-key` 0.7 stable : c'est l'un des critères de réexamen de l'ADR-0009.

## Conséquences

- **Interopérabilité vérifiée** :
  - client OpenSSH 9.x vers le serveur de l'agent : la session aboutit, et un client limité à des algorithmes hors liste est refusé ;
  - client de l'agent vers un sshd OpenSSH 9.2 de Debian 12 (`tests/ssh/debian12-target.sh`), avec une clé déposée en `restrict,from=` : la session aboutit, et une clé hôte inattendue est refusée.
- **Clients exclus** : un client trop ancien pour le strict KEX ou pour AES-GCM est refusé. C'est voulu.
- **Le grant n'apparaît pas** dans le parcours SSH de l'utilisateur. Pour RDP, il reste remis à l'utilisateur (ADR-0004).
