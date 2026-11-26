# Plan du jalon M2 : alpha interne

Ce document découpe le jalon M2 en PR, avec leurs dépendances et ce qui peut avancer en parallèle. Il est tenu à jour à chaque PR fusionnée : la colonne « État » fait foi.

## Objectif

**Démonstration.** Depuis le portail, connexion RDP en navigateur à Windows Server 2016 et 2022 membres d'un domaine ; connexion SSH native et web ; agent Windows en mode dial-back dans une zone isolée du laboratoire ; rejeu de la session RDP enregistrée.

**Critères de sortie.**

1. Lots L2 (agent passerelle), L3 (core v0, tous les modes d'authentification : LDAPS, OIDC, SAML, WebAuthn, TOTP, Kerberos SPNEGO, RADIUS, device flow) et L4 (SSH natif et web) terminés.
2. Lots L5 (RDP par navigateur), L6 (audit scellé) et L7 (portail) au niveau « fonctionnel » : critères de performance mesurés, pas encore tous tenus.
3. Installation de l'agent validée sur la matrice Windows Server 2016+ et Debian 12+.
4. Tests de non-régression nommés (`REG-RDP-*`, `REG-SEC-*`, `REG-PERF-*`) en place et verts.
5. 72 h cumulées de fuzzing sans plantage sur `ostena-frame`, SSH et chaque analyseur RDP côté client.

Reports de M1 repris ici : rôles séparés de la base, transcripts en stockage WORM, repli TCP/TLS du tunnel. La clé de publication réelle reste au lot L15.

## Règles de travail

- Une PR par ligne du tableau, branche `m2/<nom>`, base `dev`. Les PR trop grosses sont scindées en `a`, `b`…
- Chaque choix structurant a son ADR, écrit dans la PR qui l'introduit (numéros réservés ci-dessous).
- `dev` est fusionnée dans `main` (commit de fusion, sans squash) une fois tous les critères de sortie vérifiés dans `docs/demo-m2.md`.

## Découpage

### Vague 1 : socles indépendants (en parallèle)

| PR | Branche | Lot | Contenu | ADR | Dépend de | État |
|----|---------|-----|---------|-----|-----------|------|
| 1 | `m2/session` | L2 | Crate `ostena-session` : gestionnaire de sessions (quotas atomiques, identifiants en double refusés, inactivité et durée maximale, observateurs), trait `Driver` ; le relais SSH passe dessus. `REG-SEC-06`. | 0018 | — | à faire |
| 2 | `m2/tunnel-fallback` | L2 | Reconnexion automatique avec grâce pour les sessions SSH, repli TLS 1.3 sur TCP avec multiplexeur maison (mode `auto` : QUIC puis TCP après 1 s), `tunnel.fallback`. | 0008 (fin) | — | à faire |
| 3 | `m2/db-roles` | L3, L6 | Rôles PostgreSQL séparés (propriétaire DDL, application DML, audit en insertion seule) ; test qui vérifie l'absence d'`UPDATE`/`DELETE` sur les tables d'événements ; test de migration N-1 → N → N-1. | 0011 (amendement) | — | à faire |
| 4 | `m2/ssh-transfers` | L4 | `scp`, `sftp`, `rsync` soumis aux droits de transfert ; forwarding et `ProxyJump` refusés sans droit, tentative journalisée ; `ostena config ssh` ; contrôle `ssh-audit` en CI ; `REG-SEC-03`, `REG-SEC-05`. | 0010 (fin) | — | à faire |
| 5 | `m2/rdp-adr` | L5 | ADR du driver RDP : IronRDP + sspi-rs (licences, empreinte), CredSSP Kerberos joué par l'agent, épinglage du certificat de la cible, refus du repli NTLM en production, Restricted Admin, passthrough EGFX, cibles de test en CI. | 0019 | — | à faire |
| 6 | `m2/web-adr` | L7 | ADR du portail et de la passerelle web : chaîne de build hors ligne du portail, session navigateur (cookie, TOTP puis WebAuthn), WebSocket portant `ostena-frame`, CSP stricte, routes REST et OpenAPI. | 0020 | — | à faire |
| 21 | `m2/lab` | — | Laboratoire décrit en code, sans hyperviseur fourni : machines virtuelles QEMU/KVM dans les exécuteurs Linux de GitHub, Windows Server 2016 et 2022 en version d'évaluation installées sans intervention depuis les ISO de Microsoft, contrôleur de domaine AD, zone isolée sans flux entrant pour l'agent Windows ; mêmes scripts déployables plus tard sur Proxmox ou Hyper-V. | 0025 | — | à faire |

### Vague 2 : protocoles et identités

| PR | Branche | Lot | Contenu | ADR | Dépend de | État |
|----|---------|-----|---------|-----|-----------|------|
| 7 | `m2/rdp-driver` | L5 | Crate `ostena-rdp` : séquence de connexion durcie côté agent, réponses Auto-Detect, profil MCS mémorisé par cible, licences RDS de base ; cibles de fuzz X.224, MCS/GCC, TSRequest, licences ; `REG-SEC-01`, `REG-SEC-02`, `REG-RDP-03`, `REG-RDP-04`, `REG-RDP-06`, `REG-PERF-01`. | 0019 | 1, 5 | à faire |
| 8 | `m2/web-gateway` | L3, L7 | API REST du core (OpenAPI, test qui énumère les routes et vérifie le refus sans jeton), session navigateur, WebSocket `ostena-frame` du navigateur jusqu'à l'agent par le tunnel. | 0020 | 1, 6 | à faire |
| 9 | `m2/identities-ldaps` | L3 | Sources LDAPS multiples (AD multi-forêts, OpenLDAP), groupes imbriqués, bascule entre serveurs, identités `source/identifiant`, refus du clair et de StartTLS ; coupure en moins de 60 s d'un compte désactivé. | 0021 | 3 | à faire |
| 10 | `m2/pdp` | L3 | PDP v0 compilé en mémoire (groupe × groupe de comptes × protocole × fonctions), invalidation, banc < 1 ms p99 pour 10 000 autorisations et 50 000 ressources ; rôles d'administration séparés (politiques, audit). | 0022 | 3 | à faire |
| 11 | `m2/audit-l6` | L6 | Stockage en ajout seul des transcripts et enregistrements (WORM fichier), export syslog TLS RFC 5425 en OCSF, file locale chiffrée sur l'agent quand le core est injoignable, horodatage RFC 3161 des têtes. | 0012 (suite) | 3 | à faire |

### Vague 3 : navigateur, enregistrement, portail

| PR | Branche | Lot | Contenu | ADR | Dépend de | État |
|----|---------|-----|---------|-----|-----------|------|
| 12 | `m2/web-ssh` | L4 | Client SSH web (xterm.js) sur `ostena-frame`, même transcript que le SSH natif. | — | 8 | à faire |
| 13 | `m2/rdp-egfx` | L5 | Passthrough EGFX vers le navigateur et décodage WebCodecs, repli tuiles, entrées clavier et souris prioritaires ; cibles de fuzz EGFX, DRDYNVC ; banc de latence navigateur. | 0019 | 7, 8 | à faire |
| 14 | `m2/rdp-recording` | L5, L6 | Enregistrement MKV du flux H.264 tel quel, scellé par la chaîne d'audit, lecteur dans le portail ; `REG-RDP-07`. | 0023 | 11, 13 | à faire |
| 15 | `m2/identities-sso` | L3 | Plusieurs fournisseurs OIDC (code + PKCE) et SAML 2.0 simultanés (SAML initié par l'IdP désactivé par défaut, déconnexion propagée), WebAuthn/FIDO2, second facteur exigé si la source n'atteste pas d'une authentification forte. | 0021 | 8, 9 | à faire |
| 15b | `m2/identities-kerberos` | L3 | Kerberos SPNEGO (plusieurs royaumes), RADIUS, *device flow* pour la CLI. | 0021 | 8, 9, 21 | à faire |
| 16 | `m2/portal-v0` | L7 | Portail Svelte embarqué : connexion, catalogue des cibles autorisées, lancement en 2 clics (RDP et SSH), sessions et rejeu, administration minimale de l'inventaire ; thèmes clair et sombre, français et anglais ; E2E Playwright, aucune requête externe, axe. | 0020 | 8 (puis 12, 13, 14) | à faire |
| 17 | `m2/rdp-channels` | L5 | Presse-papiers et RDPDR soumis aux droits ; `REG-RDP-01`, `REG-RDP-02`, `REG-RDP-05` ; cibles de fuzz CLIPRDR, RDPDR. | 0019 | 7 | à faire |

### Vague 4 : installation, campagne et démonstration

| PR | Branche | Lot | Contenu | ADR | Dépend de | État |
|----|---------|-----|---------|-----|-----------|------|
| 18 | `m2/packaging` | L2 | MSI (installation silencieuse, paramètres en ligne de commande, déployable par GPO) et `.deb` signés avec la clé de test ; matrice d'installation en CI (Windows Server 2022 et 2025, Debian 12 et 13) ; aucun port en écoute en dial-back (scan) ; IPC refusé à un non-administrateur. | 0024 | 2 | à faire |
| 19 | `m2/fuzz-campaign` | — | Workflow de campagne : 72 h cumulées par cible (corpus repris d'un run à l'autre), rapport par cible ; plantages ajoutés au corpus de régression. | — | 7, 13, 17 | à faire |
| 20 | `m2/demo` | — | `lab/demo-m2.sh`, job CI, `docs/demo-m2.md` avec les critères de sortie et leurs preuves ; puis fusion de `dev` dans `main`. | — | toutes | à faire |

## Parallélisme

```text
Vague 1 :  1 session ─┬─────────────┐
           2 tunnel ──┼── 18 packaging
           3 db-roles ┼── 9 ldaps ── 15 sso
           │          ├── 10 pdp
           │          └── 11 audit ─────────┐
           4 ssh-transfers                  │
           5 rdp-adr ── 7 rdp-driver ─┬── 13 egfx ── 14 recording
           6 web-adr ── 8 gateway ────┤        └──── 17 channels
                              ├── 12 web-ssh
                              └── 16 portail
           21 lab ─────────────── 15b kerberos      19 fuzz-campaign ── 20 démo
```

Trois PR au plus avancent en même temps : la compilation de l'espace de travail est le goulot.

## Laboratoire

Aucun hyperviseur n'est disponible : le laboratoire est décrit en code (`lab/`, PR 21) et tourne dans la CI. Les exécuteurs Linux de GitHub exposent KVM ; un job y démarre des machines virtuelles QEMU : un contrôleur de domaine AD, Windows Server 2016 et 2022 membres du domaine, et l'agent Windows dans un segment isolé qui n'accepte aucun flux entrant et sort seulement vers le core. Les systèmes sont installés sans intervention depuis les ISO d'évaluation de Microsoft (180 jours) ; aucune image Windows n'est publiée ni conservée en artefact.

Conséquences pour la démonstration :

- elle est jouée par un job CI déclenché à la demande et chaque semaine ; Playwright pilote le portail et enregistre une vidéo de la connexion RDP, de la session SSH web et du rejeu, publiée avec le rapport du job ;
- les tests RDP de chaque PR restent rapides : serveur de test d'IronRDP et cible Windows réelle hors domaine sur les exécuteurs Windows de GitHub ; le laboratoire complet tourne chaque nuit ;
- la matrice d'installation de l'agent couvre Windows Server 2016 et 2022 dans le laboratoire, 2022 et 2025 sur les exécuteurs Windows, Debian 12 et 13 en machines virtuelles ou conteneurs ;
- le jour où un hyperviseur existe, les mêmes scripts le visent.
