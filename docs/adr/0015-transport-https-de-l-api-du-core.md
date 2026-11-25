# ADR-0015 : Transport HTTPS de l'API du core

- **Statut** : Accepté (décision du responsable du projet, 2026-11-25). Implémenté pour l'API de connexion au jalon M1, PR 7.
- **Date** : 2026-11-25

## Contexte

`ostena login` (ADR-0010, étape 1) s'authentifie auprès du core « en HTTPS ». C'est la première API HTTP du produit : jusqu'ici, le core ne parle qu'au tunnel QUIC des agents et à leur enrôlement (ADR-0008), et aucune pile HTTP n'est dans l'arbre des dépendances.

CLAUDE.md annonce pour le core une « API (axum REST + OpenAPI, tonic gRPC interne en mTLS) ». Il exige aussi une empreinte minimale, où « chaque dépendance et chaque allocation doivent se justifier ». L'API de connexion n'a que deux routes.

Les chiffres suivants ont été mesurés le 2026-11-25 sur un serveur minimal : TLS par `ostena-crypto::tls`, une route `POST` en JSON, binaire de release.

| Variante | Crates nouvelles | Binaire | Écart |
|---|---|---|---|
| tokio-rustls et JSON préfixé par sa longueur (base) | 1 | 3,70 Mio | — |
| hyper 1 (`http1`, `server`, `client`), hyper-util (`tokio`), http-body-util | 11 | 3,93 Mio | +0,22 Mio |
| axum 0.8 (`http1`, `json`) par-dessus hyper | 20 | 4,07 Mio | +0,37 Mio |

Toutes ces crates sont sous MIT ou Apache-2.0 (matchit sous MIT et BSD-3-Clause). Aucune n'apporte de deuxième version d'une dépendance existante, ni la fonctionnalité `macros` de tokio. Elles se vendorisent comme les autres (ADR-0002).

## Décision

### hyper 1 maintenant, axum avec l'API REST

- **L'API de connexion utilise hyper 1 directement**, en HTTP/1.1 seul (`http1`, `server` ; `client` pour `ostena login`), avec hyper-util (adaptateur tokio, minuterie) et http-body-util (corps borné).
- **axum est échelonné.** Il arrivera avec l'API REST d'administration et le portail. Son routeur, ses extracteurs et l'OpenAPI y paieront leurs 9 crates et 0,15 Mio. Pour deux routes, un aiguillage sur la méthode et le chemin suffit. axum est une couche sur hyper : il se branchera sur le même accepteur hyper et tokio-rustls, sans rien jeter. L'annonce de CLAUDE.md reste la cible ; seul le calendrier change.
- **Le client d'`ostena login`** utilise `hyper::client::conn::http1` sur une seule connexion, sans pool, sans résolution de mandataire, sans le client « legacy » de hyper-util.
- **Alternatives écartées** :
  - un protocole JSON maison sur QUIC, comme l'enrôlement : aucune dépendance de plus, mais l'UDP est souvent filtré depuis les postes d'administration, et ce protocole ne servirait pas au portail ;
  - un JSON préfixé par sa longueur sur TLS/TCP : il ne coûte que tokio-rustls, mais c'est un protocole de plus à maintenir et à fuzzer, à jeter quand le portail arrivera.

### TLS

- **tokio-rustls** porte les flux TLS sur tokio. La configuration reste construite par `ostena-crypto::tls` (ADR-0009) : TLS 1.3 seul, `TLS_AES_256_GCM_SHA384` seule, `SecP256r1MLKEM768` seul, ALPN `http/1.1` seul, sans reprise de session ni 0-RTT.
- **Côté core** : le certificat serveur du tunnel, signé directement par la racine hors ligne. Aucun certificat client : l'authentification se fait par mot de passe et TOTP, puis par la clé de la session.
- **Côté client** : la racine est épinglée, et seul un certificat qu'elle a signé directement est accepté (`tls::client_config`, ADR-0008). Jamais les racines du système.
- `deny.toml` admet `tokio-rustls` comme seule crate de plus autorisée à dépendre de rustls. hyper et tokio-rustls ne sont admis que sous `ostena-core` et `ostena-cli`.

### Bornes de l'écouteur de connexion

| Borne | Valeur |
|---|---|
| Connexions simultanées | `core.login.max_connections` (64), et 4 par source dès `accept`, avant la poignée de main TLS ; au-delà, la connexion est fermée aussitôt |
| Poignée de main TLS | 10 s |
| Lecture des en-têtes | 10 s ; 32 en-têtes au plus, tampon de 16 Kio |
| Échange complet | 30 s |
| Corps | 16 Kio, `Content-Type: application/json` exigé |
| Connexion persistante | non : une requête par connexion |
| Tentatives par source | `core.login.attempts_per_minute` (10), en mémoire, 10 000 sources suivies au plus |
| Source | une adresse IPv4 (aussi quand elle est vue en IPv6), ou le préfixe /64 d'une adresse IPv6, qu'un hôte ou un site détient d'ordinaire en entier : changer d'adresse dans son /64 ne contourne ni le plafond de connexions ni le limiteur |
| Journaux bruyants | `login.connection_limited` et `login.tls_refused` : une ligne par minute au plus, qui compte les refus non journalisés depuis la précédente (`unlogged`) |

## Conséquences

- Onze crates nouvelles dans le binaire Linux du core et dans `ostena login`, pour +0,22 Mio mesuré. Le binaire Windows (l'agent et `ostena login`) les lie aussi, pour le client.
- Les messages de l'API de connexion sont des types purs d'`ostena-common::api::login`, fuzzés seuls (`login_messages`) ; hyper analyse le HTTP lui-même.
- Quand axum arrivera, un ADR court ou une révision de celui-ci justifiera ses crates, mesurées de nouveau.

### Question ouverte : groupe TLS hybride et navigateurs

Les navigateurs répandus proposent l'échange hybride `X25519MLKEM768`, mais pas `SecP256r1MLKEM768`, le seul groupe retenu par l'ADR-0009 (X25519 est hors des mécanismes conformes cités par [PG-083] v3.00). L'écouteur de connexion, limité à ce groupe, ne sert qu'à `ostena login`, dont les deux extrémités sont à nous.

Le portail web demandera un arbitrage dans l'ADR-0009 avant son écouteur HTTPS. Pistes :
- admettre `X25519MLKEM768` pour le seul écouteur du portail, comme écart consigné ;
- attendre la prise en charge de `SecP256r1MLKEM768` par les navigateurs ;
- un échange classique ECDHE P-256 pour le portail, sans protection post-quantique de la confidentialité, ce qui serait un écart à `RecoSécuLongTerme`.
