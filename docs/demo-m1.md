# Démonstration du jalon M1

Le jalon M1 livre l'**accès SSH natif tracé**. L'administrateur se connecte avec `ostena login` (mot de passe et TOTP), puis utilise son client OpenSSH habituel : `ssh compte@ressource@bastion`. Le core vérifie le droit et signe un grant. L'agent passerelle ouvre la session vers la cible. Le transcript de la session est scellé dans la chaîne d'audit, et un auditeur vérifie le tout hors ligne avec la seule clé publique.

Le script [`lab/demo-m1.sh`](../lab/demo-m1.sh) joue ce parcours de bout en bout. Il utilise des processus locaux, sans Docker, et le même binaire `ostena` que celui livré. Il s'arrête à la première étape qui ne donne pas le résultat attendu. La CI le lance à chaque PR (job `demo-m1`).

## Lancer la démonstration

Prérequis sur un hôte Linux :

- PostgreSQL 16 joignable par socket Unix, en authentification `peer`, avec son compte superutilisateur `postgres` (pour `ostena core db init`) ;
- root ou `sudo` : le core tourne en production sous deux comptes système distincts (ADR-0011), `ostena_demo` pour le service et `ostena_demo_admin` pour les migrations, créés s'ils manquent puis retirés à la fin (`OSTENA_DEMO_SERVICE_USER`, `OSTENA_DEMO_MIGRATION_USER`, `OSTENA_DEMO_DB_SUPERUSER` pour d'autres noms). Ses fichiers vivent dans un dossier `/tmp/ostena-demo-core.*` qu'ils traversent : clés en credentials et transcripts à l'unique compte du service ;
- OpenSSH 9.x (client et `sshd`) et `ssh-keygen` ;
- `ip` (iproute2), plus les droits root ou `sudo`, pour créer l'espace de noms réseau de la cible ;
- la toolchain Rust du dépôt, si le binaire et le générateur TOTP doivent être construits.

```bash
lab/demo-m1.sh                                  # construit target/release/ostena s'il manque
OSTENA_BIN=/chemin/ostena lab/demo-m1.sh        # un binaire donné, par exemple celui de la CI
OSTENA_DEMO_KEEP=1 lab/demo-m1.sh               # garde le dossier de travail (journaux, export, transcripts)
```

Le script sort en 0 si tout le parcours est conforme, en 1 sinon. En cas d'échec, il affiche la fin des journaux du core et de l'agent. À la fin, il arrête ses processus, supprime l'espace de noms et la base de démonstration, et efface son dossier de travail, sauf avec `OSTENA_DEMO_KEEP=1` ou un `OSTENA_DEMO_DIR` donné.

### Pourquoi un espace de noms réseau

Le contrôle de périmètre de l'agent ([ADR-0005](adr/0005-perimetre-et-anti-ssrf.md)) refuse toujours la boucle locale et les adresses de l'hôte de l'agent. Une cible `sshd` sur `127.0.0.1` serait donc refusée, et c'est voulu. Le script place la cible dans un espace de noms réseau, relié à l'hôte par une paire veth :

| Côté | Adresse |
|---|---|
| hôte (agent) | `10.77.0.1/24` sur `ostena-d0` |
| cible (`sshd`, port 2022) | `10.77.0.2/24` sur `ostena-d1`, dans le netns `ostena-demo-<pid>` |

Le `sshd` de la cible tourne sous le compte courant (root dans un conteneur, l'utilisateur du runner en CI). Ce compte est le compte cible de la démonstration. Sa configuration est propre à la démonstration : clé d'hôte ECDSA P-256 neuve, `authorized_keys` dans le dossier de travail, mot de passe refusé.

### Sans espace de noms : une cible externe

Si `ip` ou les droits manquent, donnez une cible OpenSSH qui ne soit pas une adresse de cet hôte :

```bash
OSTENA_DEMO_TARGET=192.0.2.10:22 \
OSTENA_DEMO_TARGET_USER=demo \
OSTENA_DEMO_TARGET_HOST_KEY=cible_ecdsa.pub \
OSTENA_DEMO_AGENT_ADDR=192.0.2.1 \
lab/demo-m1.sh
```

Le fichier `OSTENA_DEMO_TARGET_HOST_KEY` contient la clé d'hôte ECDSA P-256 de la cible (`/etc/ssh/ssh_host_ecdsa_key.pub`). `OSTENA_DEMO_AGENT_ADDR` est l'adresse de cet hôte telle que la cible la voit. Le script affiche la ligne `restrict,from="…"` à déposer dans `authorized_keys` du compte cible, puis attend.

## Ce que fait le script

| Étape | Commandes du produit | Résultat attendu |
|---|---|---|
| 1. Cérémonie et clés | `ostena ca root init` (deux supports, trois parts), `ca server sign` et `ca issuing sign` avec deux parts, `ca key new` (grants, audit, CA SSH), `ca key new-mac` (empreinte des commandes, clé TOTP) | racine hors ligne, clés en credentials (`$CREDENTIALS_DIRECTORY`) |
| 2. Core | `ostena core db init` (rôles et base) sous `postgres`, `ostena core migrate` sous le compte des migrations, `ostena core run` sous celui du service, en **mode production** | `core.started`, aucun `core.database_role_weak` |
| 3. Agent | `core group add`, `core agent token`, `agent enroll`, `agent run` avec `[agent.ssh]` et un plafond local `[agent.scope]` | `agent.core_connected` ; certificat d'hôte SSH émis (`ssh.host_certified`, `agent.ssh_identity_ready`) |
| 4. Cible | netns et veth, `sshd`, `ostena agent ssh-key --from 10.77.0.1 --line` dans `authorized_keys` | la clé de l'agent est déposée en `restrict,from=` |
| 5. Inventaire | `core group policy`, `user add alice`, `resource add srv-demo` (clé d'hôte épinglée), `account add`, `right grant`, `user set-password --stdin`, `user totp-enroll` puis `--confirm` | alice : mot de passe, TOTP confirmé, droit sur le compte cible |
| 6. Connexion | `ostena login --stdin` (mot de passe, code TOTP), puis `ssh <compte>@srv-demo@bastion.demo '…'` | `login.succeeded`, `access.ssh_granted`, `access.session_opened`, `access.ssh_exec` ; la commande s'exécute sur la cible |
| 7. Transcript | — | `<session>.cast` en lecture seule (0400), avec la sortie de la session ; `transcript.sealed` |
| 8. Vérification | `core audit head`, `core audit export`, `ostena audit verify --key audit.pub --head … --transcripts copie/` | **code 0** : chaîne intacte, couverte par une tête signée, transcript conforme |
| 9. Transcript altéré | un mot changé dans la copie du `.cast`, puis le fichier supprimé | **code 1**, `AUD-E018` puis `AUD-E017` |
| 10. Export altéré | un octet changé au milieu du fichier d'export | **code 1** : signature ou chaînage (`AUD-E00x`, par exemple `AUD-E008` et `AUD-E012`) |
| 11. Base altérée | le propriétaire de la base désactive les déclencheurs et modifie un octet de l'enregistrement `transcript.sealed` | nouvel export : **code 1**, `AUD-E007` (selon l'octet touché, aussi `AUD-E001`, et `AUD-E011` ou `AUD-E013` face à la tête conservée) |

À l'étape 11, le core ne voit pas lui-même la modification : il ne recontrôle que l'enregistrement couvert par sa dernière tête signée et ceux qui le suivent (`audit.chain_broken`, `CORE-E011` au démarrage). Un enregistrement déjà couvert par une tête est prouvé par cette tête, donc par le vérificateur hors ligne et par les têtes conservées hors du bastion. C'est le fonctionnement décrit dans l'[ADR-0012](adr/0012-chaine-d-audit-du-core.md).

Les codes de `ostena audit verify` sont décrits dans la [vérification de l'audit](exploitation/audit-verification.md) : `AUD-E001` à `AUD-E020` et `AUD-W001` à `AUD-W008`.

### Deux réglages propres à la démonstration

- **Le nom du bastion.** `bastion.demo` ne se résout pas sur l'hôte de démonstration. Le fichier `ssh_config` du script ajoute donc `HostName 127.0.0.1` et `HostKeyAlias bastion.demo` avant d'inclure le fragment écrit par `ostena login`. Le certificat d'hôte de l'agent est toujours vérifié pour `bastion.demo`. Comme `HostKeyAlias` ne porte pas de port, la ligne `@cert-authority` d'`ostena login`, écrite pour `[bastion.demo]:12222`, est recopiée pour `bastion.demo` seul. En exploitation, le nom se résout et ces deux réglages sont inutiles.
- **Le code TOTP.** Le script calcule les codes qu'une application d'authentification afficherait, avec l'exemple `totp_code` d'`ostena-crypto` (`cargo build -p ostena-crypto --example totp_code`). Cet outil n'est jamais dans le binaire livré. Le code de confirmation est consommé : la connexion utilise le pas suivant, accepté à ±30 s.

### Mesure

Le script affiche le temps entre le lancement de `ssh` et la fin de la commande sur la cible, connexion comprise. L'objectif est de moins de 5 s. En local, la mesure est d'environ 0,2 s. La latence ajoutée par le relais est mesurée à part par `cargo xtask bench-ssh` (job `bench-ssh`).

## En CI : job `demo-m1`

Le job `demo-m1` vient après `release-sign`. Il :

1. télécharge l'artefact `ostena-test-signed` et vérifie la signature du manifeste avec `ostena release verify` ([ADR-0017](adr/0017-signature-des-livrables.md)) ;
2. démarre le PostgreSQL 16 du runner (socket et `peer`) et vérifie la présence d'OpenSSH ;
3. construit le générateur TOTP, puis lance `lab/demo-m1.sh` sur le binaire musl signé ;
4. écrit le tableau des étapes dans le résumé du job et, en cas d'échec, publie les journaux (artefact `demo-m1-logs`).

`ci-ok`, le contrôle requis pour fusionner, en dépend.

## Critères de sortie du jalon M1

| Critère | Preuve | État |
|---|---|---|
| `ostena login` avec mot de passe et TOTP | étapes 5 et 6 ; [ADR-0010](adr/0010-acces-ssh-natif.md), [poste d'administrateur](exploitation/connexion-administrateur.md) | fait |
| `ssh compte@ressource@bastion` avec le client OpenSSH, sans greffon | étape 6 ; certificat utilisateur, certificat d'hôte vérifié strictement | fait |
| Le core vérifie le droit et émet un grant à usage unique | étape 6 : `access.ssh_granted` ; [ADR-0014](adr/0014-inventaire-minimal-et-decision-d-acces-ssh.md), [ADR-0004](adr/0004-format-des-grants.md) | fait |
| L'agent ouvre la session vers la cible, contrôle de périmètre appliqué | étapes 4 et 6 : cible hors de l'hôte, clé de l'agent en `restrict,from=` | fait |
| Transcript écrit et scellé par la chaîne d'audit | étape 7 : `.cast` en 0400, `transcript.sealed` ; [ADR-0016](adr/0016-transcripts-des-sessions.md) | fait |
| `ostena audit verify` valide la chaîne et les transcripts hors ligne | étape 8 : code 0 ; [ADR-0012](adr/0012-chaine-d-audit-du-core.md) | fait |
| Altérations détectées : transcript, export, base | étapes 9 à 11 : `AUD-E018`, `AUD-E017`, erreurs de signature ou de chaînage, `AUD-E007` | fait |
| Établissement d'une session en moins de 5 s | étape 6 (mesure affichée) et banc `bench-ssh` | fait |
| CI complète : contrôle requis par fusion | job `ci-ok`, file de fusion (`merge_group`) ; reste à déclarer `ci-ok` comme contrôle requis sur `dev` et `main` (réglage GitHub) | fait côté code |
| CI complète : SBOM | `cargo xtask sbom`, artefact `sbom-cyclonedx` ([ADR-0002](adr/0002-chaine-de-build-hors-ligne.md)) | fait |
| CI complète : binaires signés avec une clé de test | job `release-sign`, artefact `ostena-test-signed` ([ADR-0017](adr/0017-signature-des-livrables.md)) | fait |
| Banc de latence SSH en CI, première mesure publiée | job `bench-ssh` : résumé du job et artefact `bench-ssh-latency` ; première mesure locale : 0,164 ms ajoutée au p99 pour un aller-retour de 64 octets (objectif 3 ms) | fait |
| Démonstration reproductible en CI | job `demo-m1` (ce document) | fait |
| Dépôt public | github.com/Phdhebde/Ostena, licence AGPL-3.0-or-later | fait |

Restent en dehors de M1, déjà notés : la séparation des rôles de la base (faite au jalon M2, [ADR-0011](adr/0011-socle-du-core-et-postgresql.md)), la clé de publication réelle (lot L15), la rétention WORM des transcripts ([ADR-0016](adr/0016-transcripts-des-sessions.md)) et les points de [points-a-trancher.md](points-a-trancher.md).
