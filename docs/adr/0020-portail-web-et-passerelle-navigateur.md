# ADR-0020 : Portail web et passerelle navigateur

- **Statut** : Accepté pour les sections 2 (serveur web du core ; la WebSocket `ostena-ws` avec la PR 8b), 3 (session navigateur) et 4 (passerelle navigateur : parcours, rôle du core dans le relais, contre-pression côté core et tunnel), livrées par les PR 8a et 8b, et pour les trois arbitrages rendus par le responsable du projet le 2026-11-26 (amendement de l'ADR-0009). Dans la section 4, le WebAssembly, l'ordonnanceur du navigateur et le SSH web restent proposés (PR 8c et 12). Proposé pour le reste (chaîne de build, internationalisation, tests de bout en bout dans un navigateur) : chaque partie passe à « Accepté » avec sa PR.
- **Date** : 2026-11-26
- **Révision** : 2026-11-26, PR 8a : arbitrages consignés, détails de mise en œuvre (« Mise en œuvre de la PR 8a »)
- **Révision** : 2026-11-26, PR 8b (1/3) : crate `ostena-ws` et module `ostena-crypto::websocket` (« Mise en œuvre de la PR 8b »)
- **Révision** : 2026-11-26, PR 8b (2/3) : `POST /api/v1/access`, flux navigateur du tunnel côté agent, code `GTW-E006`
- **Révision** : 2026-11-27, PR 8b (3/3) : WebSocket `/api/v1/gateway`, relais du core, événements `gateway.*`, balayage des sessions inactives, latence mesurée ; section 4 acceptée ; le grant présenté est vérifié par sa signature ECDSA (arbitrage du 2026-11-27)
- **Révision** : 2026-11-27, PR 8c (1/4) : `portal/` minimal, `cargo xtask portal`, vendorisation npm, contrôles du lockfile et des licences, budget, double construction hors ligne en CI (« Mise en œuvre de la PR 8c »)

## Contexte

Le jalon M2 livre le portail : connexion, catalogue des cibles autorisées, lancement d'une session SSH ou RDP dans le navigateur en deux clics, rejeu, administration minimale de l'inventaire (plan M2, PR 8, 12, 13, 14 et 16). C'est la première interface web du produit et le premier chemin où un navigateur porte une session jusqu'à une cible.

Ce qui existe déjà :
- l'API du core est servie par hyper 1, en HTTP/1.1 seul, derrière la configuration TLS d'`ostena-crypto` (ADR-0015). Elle n'a que deux routes, `POST /v1/login` et `POST /v1/logout`, pour `ostena login` ;
- l'authentification par mot de passe et TOTP, le verrouillage des comptes, la limite par source et les sessions de connexion révocables (ADR-0009, amendement du 2026-11-25 ; ADR-0010) ;
- le framing entre la passerelle et le navigateur (`ostena-frame`, ADR-0006), `no_std`, déjà construit en CI pour `wasm32-unknown-unknown`. Il fixe aussi le contrat de la WebSocket : grant jamais dans l'URL, `Origin` vérifiée ;
- le grant v2 (ADR-0004), émis par le core, enregistré par son jti et consommé une seule fois au `session_request` de l'agent (ADR-0014).

Contraintes :
- **hors ligne** au build comme à l'exécution (ADR-0002) ; Node est exclu en production (CLAUDE.md) ;
- **budget** : bundle compressé de moins de 400 Ko hors client WebAssembly (plan d'implémentation, L7) ;
- **latence** : 10 ms ajoutées au p99 côté navigateur ; une entrée n'attend jamais une image (ADR-0006) ;
- **sécurité** : CSP stricte sans `'unsafe-inline'`, aucun appel externe ; le poste d'administration est l'actif le plus exposé ;
- **accessibilité** RGAA 4.1 niveau AA sur les parcours principaux ; charte graphique Ostena (palette bordeaux, thèmes clair et sombre de même rang, Inter et JetBrains Mono embarquées) ;
- **dépendances** : licences de la liste de CLAUDE.md, cryptographie seulement dans `ostena-crypto`, `cargo deny` strict (`deny.toml` refuse `sha1` et `rand` hors de leurs exceptions).

### Mesures (2026-11-26, spike non fusionné)

Application Svelte représentative (connexion, catalogue, i18n, thèmes, terminal chargé à la demande), construite par Vite, Node 22, Linux x86-64 :

| Élément | Brut | gzip -9 | brotli 11 |
|---|---|---|---|
| Application et runtime Svelte 5.59 | 53,5 Ko | 20,6 Ko | 18,6 Ko |
| CSS de l'application | 0,7 Ko | 0,4 Ko | 0,3 Ko |
| xterm.js 6.0 et `addon-fit` (morceau chargé à l'ouverture d'un terminal) | 336,7 Ko | 83,8 Ko | 71,0 Ko |
| Inter variable, sous-ensemble latin (woff2) | 48,3 Ko | — | 48,3 Ko |
| JetBrains Mono 400, sous-ensemble latin (woff2) | 21,2 Ko | — | 21,2 Ko |
| **Total** | | | **≈ 160 Ko**, 40 % du budget |

- **Reproductibilité** : deux constructions successives dans des dossiers propres donnent des fichiers identiques octet pour octet (SHA-256).
- **Arbre npm** : 40 paquets installés sur Linux x86-64, dont 2 binaires de plateforme (72 entrées dans le lockfile, variantes des autres plateformes comprises), tous avec une intégrité SHA-512. Aucun script d'installation n'est nécessaire : tout se construit avec `--ignore-scripts`. Licences des 72 entrées : MIT (54), MPL-2.0 (12, `lightningcss` et ses binaires), Apache-2.0 (3), ISC, BSD-3-Clause, 0BSD. Deux outils sont des binaires natifs précompilés : `rolldown` (21 Mo) et `lightningcss` (9,6 Mo).
- **CSP stricte** (`style-src 'self'`, Trusted Types exigés) dans Chrome sans affichage :
  - Svelte 5 crée sa propre politique Trusted Types (`svelte-trusted-html`) : `require-trusted-types-for 'script'` fonctionne sans changement ;
  - le rendu DOM de xterm.js 6 crée trois éléments `<style>` : la CSP en bloque huit applications, les couleurs du terminal sont perdues ;
  - avec une cale d'une trentaine de lignes (plus bas), il n'y a plus aucune violation, et les couleurs comme le changement de thème à chaud fonctionnent.
- **WebAssembly** : un crate qui expose `ostena-frame` par wasm-bindgen compile sous `#![forbid(unsafe_code)]`. Une ABI brute (`#[unsafe(no_mangle)]`) est refusée par ce même attribut.

## Décision

### 1. Chaîne de build du portail

**Node au build seulement.** Le portail (`portal/`) est une SPA Svelte 5 + TypeScript strict, construite par Vite. Node, npm et les paquets ne servent qu'à la construction ; le binaire `ostena` n'embarque que des fichiers statiques.

**Dépendances npm figées.**
- `package.json` déclare des versions exactes (pas de `^` ni de `~`). `package-lock.json` (format 3) est versionné, et seul `npm ci` est utilisé.
- Chaque entrée du lockfile porte une intégrité SHA-512 et une adresse sur `registry.npmjs.org`. Les dépendances git, par URL ou par chemin sont refusées. Un contrôle d'`xtask` vérifie ces règles sur le lockfile.
- `--ignore-scripts` est toujours passé, et `.npmrc` le fixe aussi (`ignore-scripts=true`) : aucun code d'un paquet ne s'exécute à l'installation.
- **Séparation de ce qui part dans le bundle** : les paquets qui finissent dans le navigateur (`svelte`, `@xterm/*`, les polices) sont des `dependencies`, les outils des `devDependencies`. `npm sbom --omit dev --sbom-format cyclonedx` donne ainsi exactement les composants livrés, joints à la SBOM du binaire (ADR-0002).
- **Licences** : la liste de CLAUDE.md, contrôlée par `xtask` sur le champ `license` du lockfile, avec 0BSD (famille BSD). Pour les polices seulement : OFL-1.1, voir « Points à arbitrer ».
- **Version de Node** épinglée (`.node-version`, contrôlée par `xtask`), montée par une PR dédiée comme la toolchain Rust.

**Vendorisation.** `cargo xtask vendor` produit aussi `vendor/npm/`, un cache npm hors ligne (archives `.tgz` adressées par leur intégrité), à côté de `vendor/` pour Cargo, et pour les seules plateformes de construction (Linux x86-64 glibc). La construction isolée se fait par `npm ci --offline --ignore-scripts --cache vendor/npm`. npm refuse toute archive dont l'empreinte diffère du lockfile. Un miroir local du registre reste possible chez un client, mais ce n'est pas la voie de référence : il ajoute un service à exploiter, sans rien apporter de plus que l'intégrité du lockfile.

**Alternatives écartées** :
- versionner `node_modules` ou `portal/dist` : des dizaines de Mo de binaires natifs ou de JavaScript minifié dans un dépôt public, illisibles en revue ;
- remplacer Vite par un empaqueteur sans binaire natif (Rollup en WebAssembly) : plus lent, moins répandu avec Svelte, pour un gain limité puisque les binaires natifs sont épinglés par leur intégrité. On le reconsidérera si l'analyse de la chaîne d'approvisionnement l'exige ;
- une interface en Rust compilée en WebAssembly : bundle plus lourd, écosystème d'accessibilité plus pauvre ; CLAUDE.md fixe Svelte.

**Construction et intégration au binaire.**
1. `cargo xtask portal` lance `npm ci` puis `vite build`, sans carte de source (*source map*), compresse chaque fichier en brotli (qualité 11, par le module `zlib` de Node : aucune dépendance de plus) et écrit `portal/dist/manifest.json` : chemin, type, taille, SHA-256 de chaque fichier, et SHA-256 du manifeste lui-même.
2. Le `build.rs` d'`ostena-core` lit `portal/dist/` s'il existe et génère une table statique (`include_bytes!` des versions brute et brotli, type, ETag tiré du manifeste). Il ne fait aucune cryptographie et n'a aucune dépendance. Sans `portal/dist/`, la table est vide : le développement Rust reste possible sans Node, l'API fonctionne, et la racine du portail répond `503` avec le code `WEB-E008`.
3. `xtask check-release` refuse un binaire sans portail. `ostena core portal-manifest` affiche l'empreinte du manifeste embarqué : un évaluateur peut reconstruire le portail depuis les sources et comparer.
4. **Reproductibilité vérifiée en CI** : le portail est construit deux fois, dans deux dossiers propres, et les manifestes doivent être identiques. La signature des livrables (ADR-0017) couvre le binaire, donc le portail qu'il contient.

**Budget.** `xtask portal` échoue si la somme des fichiers compressés (brotli, polices comprises, hors `.wasm`) dépasse 400 Ko, ou si ce que charge la page de connexion dépasse 150 Ko. La CI affiche les deux valeurs à chaque PR. Le client WebAssembly a son propre suivi, sans seuil bloquant au jalon M2.

### 2. Serveur web du core

**Rester sur hyper.** L'API REST et le portail sont servis par hyper 1, comme l'API de connexion. axum n'est pas adopté. CLAUDE.md l'annonçait, et l'ADR-0015 l'avait seulement échelonné ; les raisons de l'abandonner :
- **Énumération des routes.** Le test de sécurité central (plus bas) doit parcourir toutes les routes. Le routeur d'axum ne les expose pas : il faudrait les déclarer une seconde fois, et rien ne garantirait que les deux listes concordent. Une table statique de routes est à la fois le routeur et la liste que le test parcourt.
- **WebSocket.** La fonctionnalité `ws` d'axum tire `tokio-tungstenite`, `sha1` et `rand`, que `deny.toml` refuse hors de leurs exceptions. Il faudrait de toute façon une WebSocket à nous.
- **Empreinte.** 9 crates et 0,15 Mio de plus mesurés (ADR-0015), pour un routeur que la table remplace en environ 150 lignes, et des extracteurs que des fonctions de deux lignes remplacent (corps borné, JSON strict, session).
- Les licences n'auraient pas été un obstacle : axum et ses dépendances sont sous MIT.

**Routeur.** Une table `ROUTES: &[Route]` : méthode, motif de chemin (segments fixes et paramètres typés, sans joker), accès (`Public`, `Session`, `Role(…)`), fonction. Elle est figée à la compilation. Un chemin `/api/…` inconnu reçoit `401` sans session, comme une route existante, et `404` seulement avec une session : un anonyme ne peut pas découvrir les routes.

**Écouteur.** Un écouteur `core.web`, distinct de l'écouteur de connexion. Leurs clients et leurs bornes diffèrent :
- HTTP/1.1 seul, ALPN `http/1.1` ;
- connexions persistantes, en-têtes bornés comme à l'ADR-0015, corps JSON de 64 Kio au plus ;
- plafond global de connexions et plafond par source : chaque WebSocket tient une connexion ;
- limite des tentatives de connexion et verrouillage partagés avec l'écouteur de `ostena login` : le même compteur par source, le même compteur par compte ;
- jamais de compression des réponses de l'API (attaques de type BREACH). Seuls les fichiers statiques sont servis précompressés.

Le certificat est celui du core, signé par la racine Ostena, que l'administrateur distribue aux postes (GPO). Le client peut aussi fournir un certificat de sa propre PKI pour le nom du portail (`core.web.certificate`). Ce second certificat viendra après la PR 8a ; elle sert le certificat du core. Les groupes TLS sont `SecP256r1MLKEM768` puis `X25519MLKEM768`, le repli classique seulement par une option refusée en production (ADR-0009, amendement du 2026-11-26).

**OpenAPI écrite à la main.** `crates/ostena-core/api/openapi.json` (OpenAPI 3.1) est le contrat de l'API, relu en revue comme un document. Il n'est pas généré par des macros (utoipa) : la génération ajoute des macros procédurales et leurs dépendances, et décrit le code tel qu'il est plutôt que le contrat voulu.
- Pour que le document reste fidèle au code, des tests (PR 8) vérifient que :
  - chaque route de la table est décrite, avec la même méthode et la même exigence d'authentification (`security`), et que le document ne décrit aucune route absente de la table ;
  - chaque schéma porte des exemples, et chaque exemple passe par le type Rust strict correspondant (`deny_unknown_fields`) puis se réencode à l'identique.
- Le document est embarqué et servi à `GET /api/v1/openapi.json`, aux sessions authentifiées seulement.
- Les types TypeScript du portail en sont générés au build (`openapi-typescript`, MIT, outil de build seulement).

**Test d'énumération des routes** (PR 8, puis étendu à chaque route ajoutée). Pour chaque route de la table :
- sans cookie, puis avec un cookie inconnu, expiré ou révoqué : `401` `WEB-E001`, et aucun effet en base ;
- route d'un rôle, avec la session d'un utilisateur sans ce rôle : `403` `WEB-E004` ;
- méthode qui modifie l'état, avec une session valide mais une `Origin` absente ou étrangère, ou `Sec-Fetch-Site: cross-site` : `403` `WEB-E002` ou `WEB-E003` ;
- chaque réponse, y compris d'erreur, porte les en-têtes de sécurité ci-dessous.

Le test énumère la table elle-même : une route ajoutée sans test reste couverte. Les routes `Public` sont une liste fermée, vérifiée par le test : la racine du portail et ses fichiers, `POST /api/v1/session` (connexion), `GET /api/v1/health` (`204`, sans corps) et `POST /api/v1/csp-report` (8 Kio au plus, débit limité).

**WebSocket à nous.** Un crate `ostena-ws` (RFC 6455, côté serveur) : poignée de main sur la requête hyper (`upgrade`), trames masquées exigées du client, extensions jamais négociées (pas de `permessage-deflate`), messages texte refusés, message de 32 Kio au plus. Le crate est sans dépendance, `#![forbid(unsafe_code)]`, avec des tests de propriétés et une cible de fuzz `ws_frame`. Le RD Gateway (`ostena-tsgu`, transport WebSocket) le réutilisera. La poignée de main calcule `Sec-WebSocket-Accept` par SHA-1 (RFC 6455, § 4.2.2), par le seul module `ostena-crypto::websocket` (ADR-0009, amendement du 2026-11-26).

### 3. Session navigateur

**Connexion.**
- `POST /api/v1/session` porte le nom, le mot de passe et le code TOTP en une seule requête. Il n'y a pas d'état « à moitié authentifié ». Le même authentificateur que pour `ostena login` décide (ADR-0010) : dérivation factice pour un nom inconnu, verrouillage, pas TOTP jamais accepté deux fois.
- Le succès ouvre une **session de connexion** du même registre que celles d'`ostena login`, de type `web` et sans certificat. Sa révocation (administrateur, déconnexion, désactivation du compte) coupe aussi les sessions de la passerelle ouvertes avec elle, comme pour SSH.
- Le refus ne dit jamais pourquoi (`AUTH-E001`) ; la cause est dans l'audit.

**WebAuthn ensuite** (PR 15) :
- ES256 seul (algorithme COSE −7, vérifié par `ostena-crypto`) ;
- `userVerification: "required"`, attestation `none` par défaut, RP ID égal à l'hôte de `core.web.origin` ;
- compteur de signature qui recule : refus audité ;
- la connexion se fait alors en deux temps (mot de passe, puis assertion), avec un défi lié à un cookie de pré-authentification de 2 minutes ;
- le TOTP reste un repli, qu'un réglage peut interdire.

L'analyseur des données d'authentificateur a sa cible de fuzz.

**Cookie de session.**
- `__Host-ostena_session` : `Secure`, `HttpOnly`, `SameSite=Strict`, `Path=/`, sans `Domain`, sans `Expires` ni `Max-Age`. Le préfixe `__Host-` impose les trois premiers attributs au navigateur.
- La valeur est un nombre aléatoire de 256 bits tiré par `ostena-crypto`. La base ne garde que son SHA-256 : une fuite de la base ne donne pas de session utilisable.
- Durée de vie absolue : celle de la session de connexion, `core.web.session_max_hours`, 8 h par défaut et au plus, comme pour `ostena login`.
- Inactivité : `core.web.idle_minutes`, 15 min par défaut, de 5 à 60 min. Les requêtes de fond du portail (rafraîchissement d'une liste) portent `X-Ostena-Background: 1` et ne repoussent pas l'échéance. Une session de passerelle où l'utilisateur tape compte comme une activité.
- L'échéance réelle est toujours côté serveur. Un navigateur qui restaure ses cookies au redémarrage ne prolonge rien.
- **Rotation** : la session et son identifiant ne naissent qu'à l'authentification réussie (pas de fixation de session possible), et une nouvelle valeur est émise à chaque nouvelle authentification (ré-authentification pour une action sensible, ajout d'une clé WebAuthn). Il n'y a pas de rotation périodique : ce serait une course entre requêtes concurrentes pour un gain faible, puisque le cookie est `HttpOnly`, court et révocable.
- **Liaison à la source** : la session est liée à la source qui l'a ouverte, au sens de l'ADR-0015 (adresse IPv4, ou préfixe /64 en IPv6). Une requête d'une autre source révoque la session (`web_session.source_changed`). La désactiver (`core.web.bind_source = false`) est un affaiblissement journalisé, refusé en mode production. Le guide d'exploitation demande de publier le nom du portail dans une seule famille d'adresses : un navigateur en double pile peut sinon changer de famille d'une connexion à l'autre.
- **Ré-authentification** : les actions sensibles (administration des droits, de l'inventaire, des utilisateurs) exigent une authentification de moins de 5 minutes, sinon `401` `WEB-E007` et le portail redemande les facteurs.
- **Déconnexion** : `DELETE /api/v1/session` révoque la session, efface le cookie et répond `Clear-Site-Data: "cookies", "storage"`.

**CSRF.** Pas de jeton synchroniseur. Les quatre défenses suivantes suffisent et se vérifient par test :
- `SameSite=Strict` ;
- pour toute méthode autre que `GET` et `HEAD`, `Origin` exactement égale à `core.web.origin` ;
- `Sec-Fetch-Site` égal à `same-origin` quand il est présent ;
- `Content-Type: application/json` exigé, ce qui force une requête préliminaire CORS depuis une autre origine. Le core ne répond jamais aux requêtes CORS.

Les `GET` n'ont jamais d'effet. La connexion elle-même vérifie `Origin`, contre la connexion forcée (*login CSRF*).

**CSP**, identique sur toutes les réponses :

```text
default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self';
img-src 'self'; font-src 'self'; connect-src 'self'; worker-src 'self';
manifest-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none';
require-trusted-types-for 'script'; trusted-types svelte-trusted-html;
report-to csp
```

- **Aucun `'unsafe-inline'` ni `'unsafe-eval'`**. `'wasm-unsafe-eval'` n'autorise que la compilation de WebAssembly, pas l'évaluation de JavaScript : le client WebAssembly en a besoin.
- Aucun script en ligne, y compris pour appliquer le thème avant le premier affichage : un petit script externe, `theme.js`, est chargé de façon bloquante dans `<head>`.
- Les rapports de violation vont à `/api/v1/csp-report`, et sont journalisés avec un débit limité (pas dans la chaîne d'audit : n'importe qui peut en envoyer).
- Le rejeu des enregistrements (PR 14) pourra demander `media-src 'self' blob:`. Tout ajout à cette politique passe par une révision de cet ADR et par le test E2E de la CSP.

**xterm.js sous la CSP.** Le rendu DOM de xterm.js crée des éléments `<style>` et les remplit par `textContent`. Une cale du portail (`withConstructableStyles`, une trentaine de lignes) entoure `term.open()` : pendant cet appel seulement, `document.createElement('style')` rend un `<template>` inerte dont `textContent` alimente une feuille de style construite (`CSSStyleSheet`, ajoutée à `document.adoptedStyleSheets`), que la CSP permet. Aucun `<style>` en ligne n'atteint le DOM. Le spike le vérifie : zéro violation, rendu et thème corrects. Une contribution en amont, pour que xterm.js utilise directement les feuilles construites, sera proposée ; la cale disparaîtra si elle est acceptée.

**En-têtes de sécurité**, sur toutes les réponses :

| En-tête | Valeur |
|---|---|
| `Strict-Transport-Security` | `max-age=63072000; includeSubDomains` (pas de `preload` : noms internes) |
| `X-Content-Type-Options` | `nosniff` |
| `Referrer-Policy` | `no-referrer` |
| `Cross-Origin-Opener-Policy` | `same-origin` |
| `Cross-Origin-Embedder-Policy` | `require-corp` |
| `Cross-Origin-Resource-Policy` | `same-origin` |
| `Origin-Agent-Cluster` | `?1` |
| `X-Frame-Options` | `DENY` (navigateurs anciens ; `frame-ancestors` fait foi) |
| `Permissions-Policy` | tout refusé (`camera=(), microphone=(), geolocation=(), usb=(), …`), sauf `clipboard-read=(self), clipboard-write=(self), fullscreen=(self), keyboard-map=(self)` |
| `Cache-Control` | `no-store` pour l'API et `index.html` ; `public, max-age=31536000, immutable` pour les fichiers nommés par leur empreinte |

Aucun en-tête `Server`. Les journaux du core n'écrivent jamais `Cookie`, `Set-Cookie` ni `Sec-WebSocket-Protocol`.

### 4. Passerelle navigateur

**Parcours.**
1. Le portail demande l'accès : `POST /api/v1/access` (ressource, compte, protocole). Le core décide comme pour SSH (ADR-0014) et émet un grant v2 :
   - audience : le groupe de l'agent ;
   - TTL : 60 s ;
   - liaison : la session de connexion web et le compte (ADR-0004).

   Le grant est enregistré par son jti et renvoyé au portail.
2. Le portail ouvre `wss://<origine>/api/v1/gateway` avec deux sous-protocoles : `ostena-frame.v1` et `ostena-grant.<grant en base64url>` (246 caractères, valides dans un jeton de sous-protocole). **Le grant ne passe jamais dans l'URL** (ADR-0006).
3. Avant d'accepter la poignée de main, le core vérifie, dans cet ordre :
   - `Origin` exactement égale à `core.web.origin` ;
   - le cookie de session : valide, et de la même source ;
   - la présence du sous-protocole `ostena-frame.v1` ;
   - le grant : sa signature ECDSA P-256 (ostena-grant, pour le groupe qu'il désigne), puis sa ligne du registre : émis pour **cette** session de connexion, non expiré, jamais présenté. La signature couvre tous les octets du grant : aucune comparaison d'octets n'est faite (arbitrage du 2026-11-27, qui remplace la comparaison en temps constant prévue ici).

   Le grant est alors marqué « présenté », de façon atomique : une seconde WebSocket avec le même grant est refusée (`GTW-E001`). La réponse `101` ne sélectionne que `ostena-frame.v1`, jamais le sous-protocole du grant.
4. Le core ouvre un flux du tunnel vers un agent connecté du groupe d'audience et lui transmet le grant. L'agent suit alors le chemin commun (ADR-0008, ADR-0014) :
   - il vérifie le grant et consomme son jti localement ;
   - il envoie `session_request` ; le core consomme le jti pour tout le groupe et relit les droits ;
   - il reçoit `session_params`, applique le contrôle de périmètre et ouvre le driver vers la cible.
5. Les trames `ostena-frame` circulent ensuite, un message WebSocket binaire par trame (décodage en mode message), du navigateur au core puis à l'agent, et en retour.

Un grant volé dans le navigateur ne sert à rien sans le cookie `HttpOnly` de la même session et la même source. Il ne sert qu'une fois, et pendant 60 s.

**Rôle du core dans le relais.** Le core est le premier à recevoir les données hostiles du navigateur :
- il décode chaque trame (sens `ToGateway`, bornes, séquence consécutive) et ferme la session au premier refus ;
- il relaie les octets **sans les modifier** : les numéros de séquence restent de bout en bout entre le navigateur et l'agent, et la reprise de session de l'ADR-0006 reste possible ;
- dans l'autre sens, il vérifie seulement l'en-tête ;
- l'agent revalide tout, avec sa propre instance d'`ostena-frame`.

**Contre-pression.**
- **Navigateur → cible** : l'ordonnanceur d'`ostena-frame` (priorité stricte contrôle > entrées > audit > masse, fusion des mouvements de souris) tourne dans le navigateur. Il ne confie une trame à `WebSocket.send` que si `bufferedAmount` est sous un seuil (64 Kio) : une fois remise au navigateur, une trame ne peut plus être doublée. Les envois en masse (presse-papiers, fichiers) sont fragmentés à 4 Kio. Une entrée n'attend donc jamais plus qu'un fragment.
- **Cible → navigateur** : chaque session a une file bornée dans le core (64 trames ou 1 Mio). Quand elle est pleine, le core cesse de lire le flux du tunnel. Le contrôle de flux QUIC remonte jusqu'à l'agent, qui ralentit sa source : il retarde l'acquittement des images EGFX pour RDP, il ne lit plus le canal SSH (dont la fenêtre se ferme). Aucune trame n'est jetée en silence, car la séquence casserait. Un navigateur qui ne lit plus rien pendant 30 s voit sa session fermée (`GTW-E004`, code WebSocket 4003).
- **Tunnel** : le flux d'une session interactive a une priorité QUIC plus haute que les transcripts et les transferts en masse (ADR-0008) : un dépôt de fichier sur une session ne retarde pas les frappes d'une autre.
- **Navigateur** : les entrées sont capturées sur le fil principal et envoyées sans attendre. Le décodage de l'affichage (WebCodecs, PR 13) ne se fait jamais sur ce chemin : il est fait dans un *worker*, sur un `OffscreenCanvas`. La topologie exacte est fixée par le banc de latence de la PR 13.

**Ce qui est en WebAssembly** (`ostena-web-client`, Rust, `#![forbid(unsafe_code)]`, wasm-bindgen sans `js-sys` ni `web-sys`) :
- l'encodage et le décodage des trames, la négociation, le contrôle des séquences, le réassemblage et l'ordonnanceur : le même code qu'à la passerelle, sans divergence possible (ADR-0006) ;
- la table de correspondance entre `KeyboardEvent.code` et les scancodes ;
- pour RDP (PR 13), l'analyse des commandes EGFX et le repli de décodage des tuiles.

wasm-bindgen compile sous `forbid(unsafe_code)`, contrairement à une ABI brute qui exigerait une exception à la règle (mesuré). Son outil `wasm-bindgen-cli` est épinglé à la même version exacte que le crate, construit depuis les sources vendorisées (`cargo install --offline --locked`) et contrôlé par `cargo deny` avec son propre lockfile. Ce n'est qu'un outil de build.

**Ce qui reste en TypeScript** : l'interface, les appels REST, l'ouverture de la WebSocket et ses événements, xterm.js, WebCodecs et les canevas, les API du presse-papiers et des fichiers, l'i18n et les thèmes. Rien qui touche à l'authentification ou aux droits n'est décidé dans le navigateur : le core et l'agent décident.

**SSH web (PR 12).**
- xterm.js 6 (MIT), avec `addon-fit`. Ses paquets entrent au lockfile avec leur licence, et son morceau ne se charge qu'à l'ouverture d'un terminal (71 Ko brotli).
- Les trames v1 de l'ADR-0006 ne portent pas de terminal : les trames clavier sont des scancodes, alors que xterm.js produit du texte, collages et saisie IME compris. La **version 2** d'`ostena-frame`, négociée selon l'ADR-0006 sans toucher à l'en-tête, ajoute :

  | Code | Type | Sens | Charge maximale | Classe |
  |---|---|---|---|---|
  | `0x13` | Entrée de terminal : octets UTF-8 (fragmentable) | navigateur → passerelle | 1 Kio par fragment | entrées |
  | `0x23` | Sortie de terminal : octets (fragmentable) | passerelle → navigateur | 16 Kio | masse |
  | `0x24` | Taille du terminal : colonnes, lignes (fusionnée comme `0x22`) | navigateur → passerelle | 4 o | entrées |

  L'ADR-0006 sera révisé dans la PR 12 pour les inscrire, avec leurs codes de refus.
- Côté agent, le même driver client SSH que pour l'accès natif écrit **le même transcript** (ADR-0016). Seul l'avant change : des trames reçues par le tunnel au lieu du serveur SSH de l'agent.

### 5. Internationalisation, thèmes, accessibilité

**Internationalisation.**
- Français et anglais dès la PR 16. Les catalogues sont des objets TypeScript typés : le français est la référence, et l'anglais doit avoir exactement les mêmes clés, sinon la compilation échoue.
- Pas de bibliothèque d'i18n : `Intl.PluralRules`, `Intl.DateTimeFormat` et `Intl.RelativeTimeFormat` sont dans le navigateur.
- La langue vient de la préférence de l'utilisateur (enregistrée sur le core), sinon du navigateur ; `<html lang>` suit.
- L'API renvoie des codes stables (`WEB-E…`, `GTW-E…`, `AUTH-E…`), que le portail traduit en affichant aussi le code. Il n'affiche jamais un texte libre du serveur.

**Thèmes.**
- Les jetons de couleur de la charte deviennent des propriétés CSS. Le thème clair et le thème sombre sont de même rang : le système (`prefers-color-scheme`) décide par défaut, et l'utilisateur peut imposer l'un ou l'autre (préférence locale, appliquée par `theme.js` avant l'affichage).
- `color-scheme` est déclaré pour les contrôles natifs.
- Les 16 couleurs ANSI du terminal sont déclinées pour chaque thème, avec un contraste d'au moins 4,5:1 sur le fond.
- Le symbole et les logos sont les SVG de la charte, servis comme fichiers.
- Inter et JetBrains Mono sont embarquées en woff2, sous-ensemble latin (qui couvre le français) ; JetBrains Mono est chargée avant l'ouverture d'un terminal pour que xterm.js mesure la bonne police.

**Accessibilité (RGAA 4.1 AA)**, sur les parcours connexion, catalogue, lancement, session, rejeu et administration minimale :
- composants natifs d'abord (`<button>`, `<form>`, `<table>`), repères (`<header>`, `<nav>`, `<main>`), lien d'évitement, focus toujours visible ;
- erreurs annoncées (`role="alert"`) et liées à leur champ ;
- un état n'est jamais porté par la couleur seule (charte, § 3) ; `prefers-reduced-motion` est respecté ;
- **piège au clavier** (critère 12.9) : une session RDP capture le clavier. Un raccourci documenté (Ctrl+Alt+Maj+F12, configurable) rend le focus au portail, et il est annoncé à l'ouverture de la session ;
- terminal : le mode lecteur d'écran de xterm.js (`screenReaderMode`) s'active par une préférence de l'utilisateur ;
- l'image d'un bureau distant n'est pas accessible par nature. Le contenu de la cible est hors du périmètre de conformité du portail, mais tout ce qui l'entoure doit l'être ;
- une déclaration d'accessibilité est publiée avec la v1.

### 6. Tests

**E2E Playwright** (`@playwright/test`, Apache-2.0), sur Chromium et Firefox en CI. Ils tournent contre le **vrai binaire** `ostena` (rôle core, PostgreSQL), un agent et une cible SSH de test, comme la démonstration M1.
- Parcours : connexion (mot de passe et TOTP), catalogue, lancement en deux clics, terminal SSH, déconnexion, expiration, révocation qui coupe la session ouverte.
- **Aucune requête externe, vérifiée de trois façons** :
  - chaque contexte intercepte toutes les requêtes (`context.route('**/*')`), refuse et consigne toute requête vers une autre origine que le portail, WebSocket comprise ; le test échoue s'il y en a une ;
  - Chromium est lancé avec `--host-resolver-rules="MAP * ~NOTFOUND, EXCLUDE <hôte du portail>"`, si bien qu'une résolution de nom imprévue échoue aussi ;
  - un contrôle statique de `portal/dist` refuse toute URL absolue, à l'exception d'une liste fermée : les espaces de noms XML, et les liens vers la documentation des erreurs de Svelte, qui ne sont que du texte dans les messages d'erreur.
- **CSP** : un écouteur `securitypolicyviolation` doit compter zéro violation à la fin de chaque test, et le core ne doit avoir reçu aucun rapport. La console ne doit avoir aucune erreur.
- Les navigateurs de Playwright sont téléchargés par la CI (connectée) et mis en cache. Les E2E ne font pas partie de la construction hors ligne.

**axe** (`@axe-core/playwright`, MPL-2.0) sur chaque page des parcours, dans les deux thèmes et les deux langues : zéro violation des règles `wcag2a`, `wcag2aa`, `wcag21a`, `wcag21aa`. Les mêmes parcours sont aussi rejoués au clavier seul.

**Contrastes.** Un test unitaire (`node --test`, sans dépendance) calcule le contraste de chaque couple texte/fond de la charte et des couleurs ANSI du terminal, dans les deux thèmes, et exige 4,5:1.

**Revue manuelle** RGAA à chaque version, sur une grille tenue dans `docs/` : l'automatique ne couvre qu'une partie des critères.

**Côté Rust** : le test d'énumération des routes, les tests de cohérence de l'OpenAPI, les tests de propriétés et la cible de fuzz d'`ostena-ws`, les tests du cookie (attributs, liaison, inactivité, rotation, révocation) et de la CSRF.

**Côté navigateur** : la construction d'`ostena-web-client` pour `wasm32-unknown-unknown` en CI, et ses tests en Rust natif. Le code est le même ; seule la liaison wasm-bindgen est propre au navigateur.

### 7. Découpage

La PR 8 est trop grosse pour une seule revue : elle est scindée.

| PR | Contenu |
|---|---|
| **8a** `m2/web-gateway-a` | Écouteur `core.web`, table de routes, session navigateur (mot de passe et TOTP, cookie, liaison, inactivité, ré-authentification), CSRF, en-têtes et CSP, `openapi.json` et ses tests, test d'énumération des routes, codes `WEB-E…`, événements, réglages et leurs refus en production. |
| **8b** `m2/web-gateway-b` | Crate `ostena-ws` et sa cible de fuzz, `POST /api/v1/access`, WebSocket `/api/v1/gateway` authentifiée par le grant, relais core ↔ tunnel ↔ agent avec contre-pression, codes `GTW-E…`. Testé de bout en bout par un client WebSocket en Rust. |
| **8c** `m2/web-gateway-c` | `portal/` minimal (page de connexion), `cargo xtask portal`, vendorisation npm, contrôles du lockfile et des licences, embarquement par `build.rs`, `ostena core portal-manifest`, budget, double construction en CI, `ostena-web-client` (wasm-bindgen autour d'`ostena-frame`), premier E2E Playwright : connexion, zéro requête externe, zéro violation de CSP, axe. |
| **12** `m2/web-ssh` | Trames v2 d'`ostena-frame` (révision de l'ADR-0006), xterm.js et sa cale CSP, driver SSH de l'agent alimenté par le tunnel, même transcript, E2E du terminal. |
| **16** `m2/portal-v0` | Catalogue, lancement en deux clics, sessions et rejeu, administration minimale de l'inventaire, i18n complète, thèmes, raccourci de sortie du clavier, axe et tests au clavier sur tous les parcours, test des contrastes. |

Les PR 13 (affichage RDP par WebCodecs) et 14 (lecteur des enregistrements) s'appuient sur 8b, 8c et 16 sans changer ces décisions, sauf l'ajout éventuel de `media-src` à la CSP.

### Codes et événements

Les codes sont réservés ici ; leur texte exact est fixé par la PR qui les introduit.

| Code | HTTP | Refus |
|---|---|---|
| `WEB-E001` | 401 | session absente, inconnue, expirée ou révoquée |
| `WEB-E002` | 403 | `Origin` absente ou étrangère |
| `WEB-E003` | 403 | requête intersite (`Sec-Fetch-Site`, type de contenu) |
| `WEB-E004` | 403 | rôle insuffisant |
| `WEB-E005` | 404 | route inconnue (avec une session seulement) |
| `WEB-E006` | 400, 413 | corps invalide ou trop grand |
| `WEB-E007` | 401 | ré-authentification exigée |
| `WEB-E008` | 503 | portail absent du binaire |
| `GTW-E001` | 403 | grant absent, inconnu, expiré, déjà présenté ou émis pour une autre session |
| `GTW-E002` | 400 | sous-protocole `ostena-frame.v1` absent, ou poignée de main WebSocket invalide |
| `GTW-E003` | 503 | aucun agent du groupe joignable |
| `GTW-E004` | — | navigateur trop lent (fermeture 4003) |
| `GTW-E005` | — | message WebSocket invalide : texte (fermeture 1003), trop grand (1009), trame refusée (1002), raison de fermeture hors UTF-8 (1007) |
| `GTW-E006` | — | protocole non servi dans le navigateur par l'agent (refus de l'agent sur le flux navigateur ; le grant est consommé) |

**Événements** :
- connexion : `login.succeeded`, `login.refused` et `login.locked`, avec le champ `channel` (`cli` ou `web`) ;
- session : `web_session.expired`, `web_session.source_changed`, `web_session.reauthenticated` ; `login_session.revoked` comme aujourd'hui ;
- refus : `web.origin_refused` et `web.csrf_refused`, journalisés avec un débit limité ;
- accès : `access.web_granted` (accordant, jti, agent choisi), `access.web_refused` (au mieux, code et cause) ;
- passerelle : `gateway.opened` (accordant, jti, agent), `gateway.refused`, `gateway.closed` (cause, octets dans chaque sens).

### Mise en œuvre de la PR 8a

**Routes.** La table compte dix routes :

| Méthode et chemin | Accès | Particularités |
|---|---|---|
| `GET /` | public | `503` `WEB-E008` tant que le portail n'est pas embarqué (PR 8c) |
| `GET /api/v1/health` | public | `204`, sans corps |
| `POST /api/v1/csp-report` | public | 8 Kio au plus, sans contrôle CSRF (le navigateur l'envoie de lui-même, sans les en-têtes d'une requête du portail ; la route n'a aucun effet), journalisé avec un débit limité |
| `POST /api/v1/session` | public | connexion ; `Origin` vérifiée ; limite des tentatives partagée |
| `GET /api/v1/session` | session | la session courante (utilisateur, rôles, échéances) |
| `DELETE /api/v1/session` | session | déconnexion, `Clear-Site-Data` |
| `POST /api/v1/session/reauthenticate` | session | mot de passe et TOTP de l'utilisateur de la session ; nouvelle valeur du cookie |
| `GET /api/v1/openapi.json` | session | le document embarqué |
| `GET /api/v1/login-sessions` | rôle `admin` | sessions de connexion actives, des deux canaux |
| `DELETE /api/v1/login-sessions/{id}` | rôle `admin`, authentification récente | révocation, idempotente ; `404` `WEB-E005` pour une session inconnue |

**Rôles.** La table `user_role` porte les rôles du portail ; seul `admin` existe. `ostena core user role-grant <nom> admin` et `role-revoke` les administrent, avec `user.role_granted` (accordant) et `user.role_revoked` (protecteur) dans la chaîne d'audit.

**Stockage.** La migration 0007, réversible, ajoute à `login_session` la colonne `channel` (`cli` ou `web`) ; le certificat n'est obligatoire que pour `cli`. La table `web_session` garde le SHA-256 du cookie, la source, l'heure de la dernière authentification et celle de la dernière activité. Le rôle du service (`ostena_app`) y reçoit `SELECT`, `INSERT` et `UPDATE` sur `web_session`, `SELECT`, `INSERT` et `DELETE` sur `user_role` (ADR-0011). Le retour à la migration 6 supprime ces deux tables et les sessions de connexion de type `web`, qui n'ont pas de certificat et n'existent pas dans le schéma 6 ; les sessions d'`ostena login` restent.

**Décision sur une session.** Elle est une fonction pure (`web::session::decide`), dans cet ordre : révoquée ou compte inactif, échéance absolue, changement de source, inactivité.
- L'échéance absolue répond `401` sans événement : la fin de la session de connexion est déjà portée par son échéance.
- L'inactivité et le changement de source révoquent la session et écrivent `web_session.expired` ou `web_session.source_changed`, acteur `core`.
- L'activité n'est enregistrée qu'à partir de 10 s après la précédente : l'échéance d'inactivité peut être atteinte jusqu'à 10 s plus tôt que l'inactivité réelle, jamais plus tard. Une session inactive est révoquée à sa requête suivante, ou par le balayage périodique livré avec la passerelle (PR 8b), qui coupe aussi ses sessions de passerelle.

**Écouteur.** Plafond global de connexions (`core.web.max_connections`, 256) et par source (`core.web.connections_per_source`, 16), connexions persistantes bornées à 300 s. L'origine (`core.web.origin`) est une URL `https://` sans chemin. Les groupes TLS actifs sont journalisés au démarrage (`web.tls_groups`). Codes de configuration : `CFG-V019` (section `[core.web]` invalide), `CFG-P018` (`bind_source = false`) et `CFG-P019` (`tls_classic_fallback = true`), ces deux derniers refusés en production.

**En-têtes.** Ceux du tableau plus haut, plus `Reporting-Endpoints: csp="/api/v1/csp-report"` pour la directive `report-to csp`. `Permissions-Policy` refuse aussi `publickey-credentials-create` et `publickey-credentials-get` : la PR 15 (WebAuthn) les ouvrira à `self`.

**Tests.** Le test d'énumération et les tests de la CSRF tournent sur une mémoire de sessions en processus, qui implémente le même trait que PostgreSQL (`WebBackend`) : la décision sur la session est celle de l'écouteur, quelle que soit la mémoire. Des tests contre PostgreSQL couvrent le chemin réel (connexion, ré-authentification, inactivité, changement de source, révocation par un administrateur, désactivation du compte).

**Coût mesuré** (`cargo bench -p ostena-core --bench web_request`, 2026-11-26, machine de développement, mémoire en processus) : un aller-retour `GET /api/v1/session` sur une connexion TLS persistante coûte 86 µs au p50 et 136 µs au p99, contre 77 µs et 127 µs pour la route publique `GET /api/v1/health`. L'authentification elle-même (cookie, recherche, décision, contrôles) ajoute donc environ 10 µs. La lecture dans PostgreSQL (une requête indexée par le SHA-256 du cookie) n'est pas comptée.

### Mise en œuvre de la PR 8b

La PR 8b est livrée en trois parties : le crate `ostena-ws` et le module `ostena-crypto::websocket` (1/3) ; la demande d'accès et les flux navigateur du tunnel côté agent (2/3) ; la WebSocket `/api/v1/gateway` et le relais du core (3/3).

**`ostena-ws`.** Un analyseur sans entrées-sorties (*sans-I/O*) : l'appelant remplit un tampon, `Parser::parse` rend le nombre d'octets lus et l'événement complété (message binaire, ping, pong, fermeture). Aucune dépendance, aucun runtime, `#![forbid(unsafe_code)]`.
- **Poignée de main** (`handshake::check`) : `GET` en HTTP/1.1, `Upgrade: websocket`, jeton `upgrade` dans `Connection`, `Sec-WebSocket-Version: 13` présent une seule fois, `Sec-WebSocket-Key` présent une seule fois et égal à 16 octets en base64 canonique, sous-protocoles en jetons HTTP (4 au plus, 512 octets chacun). `Sec-WebSocket-Extensions` est ignoré : rien n'est jamais négocié. L'origine, la session et le grant restent à l'appelant.
- **Trames** : masque exigé, bits réservés nuls, opcodes réservés refusés, longueur dans son encodage le plus court, trames de contrôle finales et de 125 octets au plus, suites seulement après un message commencé, aucun nouveau message avant la fin du précédent, rien après une fermeture. Le masque est retiré pendant la copie dans le tampon du message : une seule copie.
- **Borne** : 32 Kio par message, vérifiée sur le champ de longueur **avant** la lecture de la charge : un client ne peut pas faire tamponner davantage au core.
- **Codes de fermeture** : 1003 pour un message texte (la RFC le prévoit pour un type de données refusé, plutôt que 1002 annoncé plus haut), 1009 pour un message trop grand, 1007 pour une raison de fermeture hors UTF-8, 1002 pour le reste. Le tableau des codes est mis à jour.
- **Côté client** : une fonctionnalité `client` (trames masquées, opcodes et bits quelconques pour forger ce que le serveur doit refuser) sert aux tests de la passerelle et à la cible de fuzz. Elle n'entre jamais dans le binaire.
- **Tests** : vecteurs de la RFC 6455 (§ 5.7), chaque refus avec son code, tests de propriétés (messages fragmentés et pings mêlés, masque quelconque, lectures découpées au hasard : mêmes messages), cible de fuzz `ws_frame` (mêmes événements quel que soit le découpage des lectures, aucun message au-delà de la borne, poignée de main sur les mêmes octets), corpus rejoué par les tests stables.

**`ostena-crypto::websocket`.** `accept_key` rend `base64(SHA-1(clé ‖ GUID))` par `SHA1_FOR_LEGACY_USE_ONLY` d'aws-lc-rs, et rien d'autre (ADR-0009, amendement du 2026-11-26). Le crate `sha1` reste refusé par `deny.toml`.

**Demande d'accès (2/3).** `POST /api/v1/access` (session exigée, contrôles CSRF de toutes les routes à effet) prend `{resource, account, protocol}`, protocole `ssh` seulement tant que l'affichage RDP n'est pas livré (PR 13).
- La décision est celle de l'ADR-0014, dans une transaction : utilisateur actif, session de connexion valide, ressource, compte, droit valide, verrouillés ; durée de session la plus courte du droit, de sa fin et de la session de connexion.
- Le core choisit l'agent connecté du groupe qui a le moins de flux ouverts ; sans agent, `503` `GTW-E003`. Le grant (audience le groupe, 60 s, lié à la session de connexion et au compte) est enregistré par son jti dans `access_grant`, avec `channel = 'web'` et l'agent choisi, et l'enregistrement accordant `access.web_granted` est écrit dans la même transaction.
- Un refus rend le code et son libellé générique (`ACC-E…`, `INV-E…` en `403`) ; la cause va dans `access.web_refused` (au mieux). Les demandes d'une session sont limitées (10 d'un coup, puis une toutes les 6 s ; `429` `ACC-E009`, sans événement de chaîne).
- La migration 0010, réversible, ajoute à `access_grant` les colonnes `channel` (`cli` ou `web`) et `presented_at` (heure de présentation par la WebSocket, seulement pour `web`). Le retour à la migration précédente supprime les grants `web`, leurs sessions et leurs transcripts.

**Flux navigateur du tunnel (2/3).** Le core ouvre un canal du tunnel par session navigateur, classe interactive : les entrées du navigateur passent devant les transcripts et les transferts (ADR-0008). Sur ce canal (`ostena_tunnel::browser`) :
- le core envoie `[version 1][longueur u16][grant]` ;
- l'agent vérifie le grant et consomme son jti dans son journal, refuse un protocole qu'il ne sert pas dans le navigateur (`GTW-E006`, avant toute demande au core : un grant présenté une fois est brûlé), puis suit le chemin commun (`session_request`, `session_params`, contrôle de périmètre) ;
- il répond `[0][identifiant de session]` ou `[1][code du refus]`, puis passe son demi-flux en classe affichage ;
- les trames `ostena-frame` se suivent ensuite, auto-délimitées, dans les deux sens. La contre-pression est le contrôle de flux du canal : un lecteur qui ne lit plus arrête l'écrivain à l'autre bout.

L'agent remet chaque session à un driver navigateur (trait `BrowserDriver`) puis rapporte sa fin au core (`session_closed`, octets dans chaque sens). Le binaire de la PR 8b n'a aucun driver navigateur (`NoDriver`) : chaque flux est refusé par `GTW-E006` après consommation du grant. Le terminal SSH arrive avec la PR 12, l'affichage RDP avec la PR 13. Le tunnel accepte désormais les canaux ouverts par le core (file de 16, puis la limite de flux du tunnel) ; seuls les canaux de classe interactive sont servis.

Événements de l'agent (journal structuré) : `agent.browser_opened`, `agent.browser_refused` (code), `agent.browser_closed` (cause, octets dans chaque sens), `agent.channel_refused` (en-tête de canal invalide ou classe non servie).

**WebSocket et relais (3/3).** `GET /api/v1/gateway` (session exigée) est vérifiée dans l'ordre du parcours : `Origin` (`WEB-E002`), cookie (`WEB-E001`), poignée de main et `ostena-frame.v1` (`GTW-E002`), puis le grant, présent exactement une fois dans `ostena-grant.<grant>` (`GTW-E001`).
- **Grant** : signature ECDSA vérifiée par `ostena-grant` pour le groupe qu'il désigne, puis, dans une transaction, `UPDATE access_grant SET presented_at` sur la ligne `web` de cette session de connexion, non expirée, jamais présentée ni consommée. L'enregistrement **accordant** `gateway.opened` (jti, groupe, agent) est écrit dans la même transaction : une seconde WebSocket avec le même grant est refusée (`GTW-E001`). Côté agent, `session_request` refuse un grant `web` jamais présenté (`ACC-E008`) : un grant du portail n'ouvre de session que par sa WebSocket.
- **Agent** : celui choisi à l'émission, sinon un autre agent connecté du groupe ; sans agent, `503` `GTW-E003`. Le core ouvre le flux navigateur et attend la réponse de l'agent **avant** le `101` : un refus de l'agent est rendu en HTTP (`GTW-E006`, ou `GTW-E001` pour les autres codes, le code de l'agent allant dans `gateway.refused`).
- **Relais** : chaque message binaire du navigateur doit être une trame `ostena-frame` vers la passerelle, décodée et acceptée par un `Receiver` (version, séquence consécutive, fragmentation), puis écrite telle quelle dans le flux. La version négociée est apprise du `HelloAck` de l'agent. Vers le navigateur, les trames sont découpées par leur en-tête, vérifié (sens, type, longueur), et mises dans une file de 64 trames : pleine, le core cesse de lire le flux, et le contrôle de flux du tunnel ralentit l'agent. Une écriture vers le navigateur bloquée 30 s ferme la session (4003, `GTW-E004`).
- **Fermetures** : 1000 (fin par l'agent ou le navigateur), 1002 (trame refusée, `GTW-E005`), 1003, 1007, 1009 (message WebSocket refusé, `GTW-E005`), 1008 (session de connexion révoquée), 1011 (trame de l'agent refusée), 4003 (navigateur trop lent).
- **Révocation** : la révocation d'une session de connexion (déconnexion, administrateur, inactivité, changement de source) coupe à l'instant ses sessions de passerelle, à la réception de la notification de révocation par le core.
- **Inactivité** : les trames du navigateur gardent la session active (enregistrée au plus toutes les 10 s). Toutes les 30 s, le core révoque les sessions du portail inactives (`web_session.expired`), ce qui coupe leurs sessions de passerelle sans attendre une requête.
- **Connexions** : une WebSocket garde sa place dans le plafond global et dans celui de sa source jusqu'à sa fin.
- **Événements** : `gateway.opened` (accordant), `gateway.refused` (au mieux : code, cause, dont le code de l'agent), `gateway.closed` (au mieux : session, jti, cause, octets reçus du navigateur et envoyés vers lui). Journal structuré : `gateway.cut`, `web.sessions_swept`.

**Latence mesurée** (2026-11-27, machine de développement, boucle locale, build de test non optimisé) :
- aller-retour complet navigateur → core → agent → core → navigateur, WebSocket sur TLS 1.3 hybride, trames `Ping`/`Pong` d'`ostena-frame`, 500 mesures (`tests/web_gateway.rs`) : p50 0,66 à 0,87 ms, p99 1,3 à 2,0 ms ;
- le flux navigateur du tunnel seul, core → agent → core (`ostena-tunnel`, `tests/gateway.rs`) : p50 0,36 ms, p99 0,98 ms.

La part du relais WebSocket (TLS, décodage, contrôle des trames, file) est donc d'environ 0,3 à 0,5 ms au p50 et 1 ms au p99, pour un aller-retour : bien sous l'objectif de 10 ms au p99 pour le navigateur.

### Mise en œuvre de la PR 8c

La PR 8c est livrée en quatre parties : la chaîne de build du portail (1/4) ; son embarquement dans le binaire et `ostena core portal-manifest` (2/4) ; `ostena-web-client` (3/4) ; le premier E2E Playwright (4/4).

**Chaîne de build (1/4).**
- **Paquets** (`portal/package.json`, versions exactes, toutes publiées depuis plus de deux semaines) :
  - livrés au navigateur (`dependencies`) : `svelte` 5.57.3 (MIT) et `@fontsource-variable/inter` 5.3.0 (OFL-1.1, police) ;
  - outils (`devDependencies`) : `vite` 8.3.8 (MIT, qui tire `rolldown` 1.2.19 et `lightningcss` 1.33.0, MPL-2.0), `@sveltejs/vite-plugin-svelte` 7.3.1, `typescript` 6.0.3 (Apache-2.0) et `svelte-check` 4.7.8 (vérification stricte des types, composants Svelte compris).
  - Le lockfile compte 79 entrées (variantes des autres plateformes comprises) : MIT (59), MPL-2.0 (12), Apache-2.0 (4), ISC, BSD-3-Clause, 0BSD et OFL-1.1 (la police).
- **Reportés** : JetBrains Mono arrive avec le terminal (PR 12) ; `openapi-typescript` avec le portail complet (PR 16). Les trois appels de la page de connexion sont typés à la main dans `src/api.ts`.
- **Contrôles d'`xtask`** (`cargo xtask portal`, sans dépendance : un petit lecteur JSON strict) :
  - Node : la version qui tourne est exactement celle de `portal/.node-version` (22.23.5) ;
  - `package.json` : versions exactes, ni `optionalDependencies`, ni `peerDependencies`, ni `bundleDependencies` ; `.npmrc` fixe `ignore-scripts=true` ;
  - lockfile : format 3 ; chaque entrée vient de `registry.npmjs.org` (archive `.tgz`), porte une seule intégrité SHA-512, une version exacte et une licence admise (expression SPDX : une alternative dont tous les termes sont admis). OFL-1.1 n'est admise que pour les polices d'une liste fermée, et seulement parmi les `dependencies` ;
  - un paquet qui déclare un script d'installation doit figurer dans une liste fermée, relue en revue (`fsevents`, macOS seulement, jamais installé sur les plateformes de construction). Aucun script ne s'exécute de toute façon.
- **Construction** : `npm ci --ignore-scripts` (avec `--offline --cache vendor/npm` dès que `vendor/npm/` existe ; `cargo xtask portal --offline` l'exige), `svelte-check`, `vite build`, puis `scripts/pack.mjs` (modules de Node seulement) :
  - refuse toute URL absolue dans ce que le navigateur interprète (HTML, JS, CSS, SVG, JSON), hors de la liste fermée (espaces de noms XML, documentation des erreurs de Svelte) ;
  - écrit `licenses.txt`, les licences des paquets livrés (dont l'OFL de la police), servi avec le portail ;
  - compresse chaque fichier texte en brotli (qualité 11), gardé seulement s'il est plus petit ; les `woff2` ne sont pas recompressés ;
  - écrit `SHA256SUMS`, au format de `sha256sum`, trié par chemin : chaque fichier servi, variantes brotli comprises. **L'empreinte du manifeste** est le SHA-256 de ce fichier. Un évaluateur la recalcule sans outil d'Ostena : `sha256sum --check SHA256SUMS && sha256sum SHA256SUMS` ;
  - écrit `manifest.json` : chemin, type, taille et SHA-256 de chaque fichier et de sa variante brotli, l'empreinte, la liste des fichiers de la page de connexion et les trois mesures du budget.
- **Budget** : en octets (1 Ko = 1 000 o), 400 000 pour le total et 150 000 pour la page de connexion, mesurés sur ce qui part compressé. La page de connexion est `index.html`, `theme.js`, l'icône, et le morceau d'entrée de Vite avec ses imports statiques, ses feuilles de style et leurs fichiers (manifeste de Vite, retiré ensuite). `xtask portal` échoue au-delà et écrit les mesures dans le résumé du job.
- **Vendorisation** : `cargo xtask vendor` remplit aussi `vendor/npm/` (cache npm, archives adressées par leur intégrité) ; `cargo xtask vendor npm` ne fait que cette partie.
- **SBOM** : `cargo xtask sbom` écrit `ostena-portal.cdx.json` (CycloneDX 1.5) depuis le lockfile : les paquets livrés, avec licence, URL et SHA-512. Il n'utilise pas `npm sbom`, dont `--omit dev` retire un paquet livré dès qu'un outil en dépend aussi (`svelte`, dépendance de `@sveltejs/vite-plugin-svelte`).
- **CI** (job `portal`) : `cargo xtask vendor npm` (connecté), puis deux constructions `--offline` dans deux copies propres des sources, avec un registre injoignable ; `manifest.json` doit être identique octet pour octet, et les deux arbres aussi. Le portail construit est un artefact, pour que les binaires Linux et Windows embarquent le même.
- **Mesures** (2026-11-27) : page de connexion 62,9 Ko, total 68,2 Ko (brotli, police comprise), soit 17 % du budget. Deux constructions, en ligne et hors ligne, dans deux dossiers différents : même empreinte.

**Page de connexion.** Un formulaire natif (identifiant, mot de passe, code à usage unique) envoie `POST /api/v1/session` ; l'erreur est annoncée (`role="alert"`), liée aux champs, et affiche toujours le code stable. Lien d'évitement, repères `header` et `main`, focus visible, `prefers-reduced-motion` respecté. Les jetons de couleur de la charte sont des propriétés CSS ; le thème clair et le thème sombre sont de même rang, le système décide, et `theme.js` applique avant l'affichage un thème imposé par l'utilisateur. Une session ouverte affiche l'utilisateur et un bouton de déconnexion (`DELETE /api/v1/session`). Le français seul en attendant l'i18n de la PR 16.

## Conséquences

- **Node** entre dans la chaîne de build, jamais dans le produit. La construction hors ligne demande `vendor/npm/` et la version épinglée de Node, à transférer comme la toolchain Rust.
- **Binaires précompilés** : deux outils de build sont des binaires natifs précompilés (`rolldown`, `lightningcss`), épinglés par leur intégrité mais non reconstruits depuis les sources. C'est un risque de chaîne d'approvisionnement accepté et consigné, à revoir pour la CSPN (empaqueteur en WebAssembly, ou reconstruction).
- **Taille du binaire** : le core embarque le portail en version brute et brotli, environ 0,6 Mio aujourd'hui. `xtask footprint` le mesure. Cet ajout volontaire est consigné, et n'est pas une régression.
- **Écart à CLAUDE.md** : axum n'est pas adopté. La ligne « axum REST + OpenAPI » de CLAUDE.md est devenue « hyper, routeur à table statique + OpenAPI » (PR 8a).
- **Nouveau crate** : `ostena-ws` (protocole, sans dépendance, fuzzé).
- **Framing** : `ostena-frame` passe en version 2 pour le terminal. L'en-tête ne change pas ; la v1 reste négociable.
- **Cale CSP** : xterm.js dépend d'une cale CSP tant que l'amont n'utilise pas les feuilles de style construites. Une montée de version de xterm.js doit repasser le test E2E de la CSP.
- **Liaison à la source** : elle peut couper la session d'un poste en double pile ou en mobilité. C'est voulu ; le guide d'exploitation l'explique.

## Arbitrages (2026-11-26)

Le responsable du projet a retenu les trois propositions ; elles sont consignées dans l'amendement du 2026-11-26 de l'ADR-0009.

1. **Groupes TLS des navigateurs.** Sur l'écouteur `core.web` seulement : `SecP256r1MLKEM768`, puis `X25519MLKEM768`, admis comme écart. Le repli classique `secp256r1` n'existe que par `core.web.tls_classic_fallback`, journalisé et refusé en production (`CFG-P019`). rustls suit l'ordre du client : la garantie est que tout échange accepté est hybride, pas que `SecP256r1MLKEM768` soit choisi. L'écouteur de `ostena login` et le tunnel restent inchangés.
2. **SHA-1 dans la poignée de main WebSocket.** Admis pour `Sec-WebSocket-Accept` seulement, dans le module `ostena-crypto::websocket` (`SHA1_FOR_LEGACY_USE_ONLY` d'aws-lc-rs), qui arrivera avec la PR 8b. Le crate `sha1` reste refusé.
3. **Licence des polices.** OFL-1.1 est admise pour les seules polices embarquées, avec leur licence livrée dans le paquet et dans la SBOM (CLAUDE.md).
