# ADR-0019 : Driver RDP et passthrough vers le navigateur

- **Statut** : Proposé. L'écart cryptographique propre à RDP et le profil TLS des cibles Windows sont décidés (amendement de l'ADR-0009 du 2026-11-26, PR 7). Restent à trancher : le stockage des mots de passe des comptes de ressource sur l'agent tant que le coffre-fort n'existe pas, et l'écart d'empreinte (voir « Points à trancher »). Mise en œuvre de la PR 7 : section 9.
- **Date** : 2026-11-26

## Contexte

Le jalon M2 ouvre l'accès RDP par le navigateur : depuis le portail, l'administrateur ouvre une session sur un Windows Server 2016 ou plus récent, membre d'un domaine ou non. L'agent passerelle (Windows Server 2016+ et Debian 12+) ouvre la session RDP vers la cible et y joue l'authentification. Le navigateur reçoit l'image par `ostena-frame` (ADR-0006), au travers du core et du tunnel (ADR-0008, ADR-0020).

Exigences :

- **première image en moins de 5 s** (p95), du clic dans le portail à la première image peinte ;
- **latence ajoutée d'au plus 10 ms** (p99) dans le navigateur, hors propagation sur le réseau ;
- **enregistrement MKV du flux H.264 tel quel**, sans transcodage, scellé par la chaîne d'audit ;
- **le grant porte l'autorisation, jamais le secret** (ADR-0004) ;
- refus en production de ce qui affaiblit la sécurité (ADR-0003) : certificat de la cible ni épinglé ni validé par une PKI (`CFG-P002`), repli NTLM alors qu'un mot de passe est délégué (`CFG-P003`) ;
- crates protocolaires sans base ni API, *fuzzables* seules ; `#![forbid(unsafe_code)]` ; agent sobre ;
- ni client ni passerelle RDP externes (exclus par CLAUDE.md) : uniquement des bibliothèques Rust liées dans le binaire.

Les références sont les spécifications publiques : [MS-RDPBCGR] (séquence de connexion, PDU de base), [MS-CSSP] (CredSSP), [MS-RDPEGFX] (pipeline graphique), [MS-RDPELE] (licences), [MS-RDPEFS] (redirection de fichiers), [MS-RDPECLIP] (presse-papiers), [MS-RDPEDISP] (taille de l'affichage).

## Décision

### 1. Bibliothèques : IronRDP et sspi-rs, épinglés exactement

`ostena-rdp` s'appuie sur **IronRDP** (codecs des PDU, machine d'état de la séquence de connexion, canaux statiques et dynamiques) et **sspi-rs** (CredSSP, SPNEGO, Kerberos, NTLM). Les deux sont en Rust pur, sous `MIT OR Apache-2.0`. L'alternative, une pile RDP entièrement écrite par nous, représente plusieurs dizaines de milliers de lignes (le seul `ironrdp-pdu` en compte 34 000) : hors de portée du jalon, et moins éprouvée.

**Versions épinglées** (`=`), toutes de la génération publiée le 2026-10-27 :

| Crate | Version | Rôle | Où |
|---|---|---|---|
| `ironrdp-pdu` | `=0.11.0` (`std`) | codecs X.224, MCS/GCC, licences, capacités, fast-path, auto-détection | agent |
| `ironrdp-core` | `=0.3.1` | lecture et écriture bornées | agent |
| `ironrdp-connector` | `=0.12.0` | séquence de connexion côté client | agent |
| `ironrdp-svc`, `ironrdp-dvc` | `=0.10.0` | canaux statiques, DRDYNVC | agent |
| `ironrdp-egfx` | `=0.5.0`, sans fonctionnalité | PDU du pipeline graphique (module `pdu` seulement) | agent, navigateur |
| `ironrdp-graphics` | `=0.11.0` | ZGFX côté agent ; Planar, ClearCodec, RemoteFX côté navigateur | agent, navigateur |
| `ironrdp-displaycontrol` | `=0.10.0` | changement de taille ([MS-RDPEDISP]) | agent |
| `ironrdp-cliprdr`, `ironrdp-rdpdr` | `=0.9.0` | presse-papiers, redirection de lecteurs (PR 17) | agent |
| `sspi` | `=0.23.0`, `default-features = false` | CredSSP, SPNEGO, Kerberos, NTLM | agent |
| `picky` | `=7.0.0-rc.26` (transitive) | X.509, clés ; version préliminaire imposée exactement par `ironrdp-connector` et `sspi` | agent |
| `ironrdp-acceptor` | `=0.12.0` | séquence côté serveur, **tests seulement** | dev |

- `sspi` 0.23.1 est **incompatible** avec `ironrdp-connector` 0.12.0 : l'un exige `picky =7.0.0-rc.27`, l'autre `=7.0.0-rc.26` (mesuré). On reste en 0.23.0.
- `ironrdp-server` n'est **pas** retenu pour les tests : sa dernière version (0.13.0) dépend de la génération précédente (`ironrdp-pdu` 0.9) et doublerait tout l'arbre. Le serveur de test est construit sur `ironrdp-acceptor` de la même génération (section 7).
- Ne sont pas retenus : `ironrdp-session` (son `ActiveStage` décode l'image dans un tampon de 8 Mio par session en 1080p, ce que le passthrough évite), `ironrdp-async`, `ironrdp-tokio`, `ironrdp-tls` (la TLS passe par `ostena-crypto`), et la fonctionnalité `openh264` d'`ironrdp-egfx` (décodage dans l'agent).
- IronRDP publie souvent, en cassant l'API (deux versions majeures en une semaine en octobre 2026). Une montée de version est une PR à part, avec les cibles de fuzz et les tests de bout en bout rejoués.

**Arbre de dépendances** (mesuré le 2026-11-26 sur un projet d'essai hors de l'espace de travail, cible `x86_64-unknown-linux-musl`, arbre normal, avec l'épinglage `idna_adapter = "=1.0.0"` de l'espace de travail) :

- **199 crates**, dont environ **65 absentes** du `Cargo.lock` actuel ; les autres sont déjà là (RustCrypto de la même génération que russh : `p256` 0.14, `sha2` 0.11, `hmac` 0.13, `aes` 0.9, `digest` 0.11…). Windows ajoute les crates `windows*` 0.62 tirées par `sspi` (registre, DNS, magasin de certificats).
- **Licences** : toutes dans la liste de `deny.toml` (MIT, Apache-2.0, BSD-3-Clause pour `subtle` et les `*-dalek`, ISC pour `libloading` et `untrusted`, Zlib). Seule `unicode-ident` porte Unicode-3.0, déjà admise. **Sans l'épinglage d'`idna_adapter`, `url` (tiré par `sspi` et `ironrdp-connector`) amènerait 18 crates `icu_*` sous Unicode-3.0** : l'épinglage existant les écarte.
- **Doublons nouveaux** à déclarer dans `deny.toml` (`skip`, avec raison) : `hmac` 0.12, `md-5` 0.10, `pkcs1` 0.7 avec `der` 0.7, `spki` 0.7, `const-oid` 0.9, `pkcs8` 0.10 (tous par `ironrdp-pdu`) ; `getrandom` 0.3 (`sspi`, `ironrdp-rdpdr`) ; `rand` 0.9, `rand_core` 0.9, `rand_chacha` 0.9 (`ironrdp-connector`) ; `crypto-mac` 0.11 (`sspi`) ; `synstructure` 0.13 (compilation seulement).
- **`cargo deny`** avec le `deny.toml` actuel, sur le projet d'essai : `check licenses` passe ; `check bans` relève ces doublons et les crates cryptographiques interdites hors de leurs enveloppes actuelles (`aes`, `aes-gcm`, `cbc`, `ctr`, `des`, `hmac`, `md-5`, `p256`, `p384`, `p521`, `pbkdf2`, `rand`, `sha1`, `sha2`, `sha3`, `ed25519-dalek`, `curve25519-dalek`), ce qu'attend l'écart de la fin de cet ADR. Des crates nouvelles sont à interdire hors de la chaîne d'`ostena-rdp` : `md4`, `rc2`, `rsa`, `aes-kw`, `x25519-dalek`, `crypto-mac`, `picky*`, `sspi`, `ironrdp-*`.
- **Code natif** : `libz-sys` (zlib en C, compilée par `cc`), par `winscard`, et `libloading` (chargeur de bibliothèques PKCS#11), par `cryptoki`. Les deux viennent de la fonctionnalité `scard` de `sspi`, **imposée** par `ironrdp-connector` pour la carte à puce émulée. Le binaire d'essai importe `dlopen`. Ostena n'utilise jamais la carte à puce ; un correctif amont rendant `scard` optionnel est proposé (section « Correctifs amont »). D'ici là, ces chemins sont liés mais inatteignables : `ostena-rdp` ne construit jamais d'identité carte à puce, et un test le vérifie.

**Code `unsafe`** (relevé dans les sources publiées) : aucun dans les crates IronRDP retenues ; 32 lignes dans `sspi` (DNS Windows, extraction de certificats Windows pour PKU2U, carte à puce, chaînes UTF-16), 4 dans `picky`, 2 dans `picky-asn1`, 119 dans `cryptoki` (FFI PKCS#11). `ostena-rdp` reste en `#![forbid(unsafe_code)]`. Aucun des chemins `unsafe` de `sspi` n'est emprunté par Ostena : la découverte DNS du KDC est coupée (le KDC est toujours configuré), PKU2U et la carte à puce ne sont jamais demandés.

**Empreinte** (mesurée sur le même projet d'essai, x86_64 glibc, profil de release d'Ostena : `opt-level = "s"`, LTO complète, une unité de génération, symboles retirés) : un client qui lie la séquence de connexion, CredSSP Kerberos et NTLM, DRDYNVC, les PDU EGFX, le presse-papiers, RDPDR et la taille d'affichage pèse **3,14 Mo**, contre **0,30 Mo** pour le même squelette d'entrées-sorties sans RDP : **+2,84 Mo** de binaire, dont +2,57 Mo de code (`.text`) et +0,27 Mo de données. Dans le binaire `ostena`, une partie est déjà présente (RustCrypto, `tracing`, `serde`, `time`, `url`) : l'écart attendu est de **+2 à +2,8 Mo**, à remesurer dans la PR 7 avec la méthode de l'ADR-0009. Comme pour SSH, ce sont surtout des pages de code, chargées à la demande : la mémoire résidente d'un agent au repos doit peu bouger, mais l'écart dépassera probablement le seuil de 1 Mio de la définition de « terminé », et demandera la même décision explicite que pour SSH. Les crates du chemin de données (`ostena-rdp`, `ironrdp-pdu`, `ironrdp-core`, `ironrdp-dvc`, `ironrdp-egfx`, `ironrdp-graphics`) rejoignent la liste `opt-level = 3` du profil de release (ADR-0009). Compilation de ces dépendances : 2 min 39 s avec deux tâches.

**Mémoire par session** (estimation, passthrough) : historique ZGFX 2,5 Mio (taille fixée par [MS-RDPEGFX]), tampons TLS et de lecture environ 100 Kio, réassemblage DRDYNVC et `ostena-frame` bornés à 4 Mio au pire, alloués à la demande. **Aucun tampon d'image dans l'agent** : 8 Mio économisés par session 1080p par rapport à un décodage dans l'agent.

**Ce qu'Ostena écrit lui-même** :

- la **TLS vers la cible** et la validation de son certificat, dans `ostena-crypto` (section 3) ;
- le **pilotage de CredSSP** sur `sspi::credssp::CredSspClient` (et non `ironrdp_connector::credssp::CredsspSequence`, qui laisse SPNEGO replier sur NTLM et ne sait pas demander le Restricted Admin), avec le **transport KDC** (TCP, contrôle de périmètre) ;
- une **garde de séquence** qui contrôle, et au besoin réécrit, les deux PDU sortantes que le connecteur ne laisse pas paramétrer : la requête X.224 (drapeau Restricted Admin) et le bloc GCC `TS_UD_CS_CORE` (`earlyCapabilityFlags`) ;
- la **boucle de session active** (démultiplexage fast-path et slow-path, auto-détection continue, battements, informations d'erreur, désactivation-réactivation), sans décodage d'image ;
- le **client EGFX en passthrough**, sur le module `pdu` d'`ironrdp-egfx` (et non `GraphicsPipelineClient`, qui décode) ;
- le **cache de licences** et le **profil de cible**, conservés par le core ;
- dans le navigateur, le décodage WebCodecs et le rendu (PR 13).

**Correctifs amont** à proposer, sans bloquer le jalon : rendre `scard` optionnel dans `ironrdp-connector` ; exposer les drapeaux de la requête X.224 et les `earlyCapabilityFlags` dans `Config` ; remplacer deux `unwrap()` sur des données reçues du KDC dans `sspi` (`kerberos/client/extractors.rs` : liste d'`etype` vide, panique sur une réponse forgée ; voir section 7). S'ils sont acceptés, la garde de séquence se réduit à une vérification.

**Condition de sortie.** Si la fonctionnalité `scard` ne devient pas optionnelle, ou si l'API du connecteur empêche la garde de séquence, `ostena-rdp` remplace `ironrdp-connector` par sa propre séquence sur `ironrdp-pdu` (environ 2 000 lignes estimées), en gardant les mêmes tests.

### 2. Authentification : CredSSP avec Kerberos joué par l'agent

**Pas de connexion sans NLA.** L'agent ne propose que `PROTOCOL_HYBRID` et `PROTOCOL_HYBRID_EX` ([MS-RDPBCGR] 2.2.1.1.1) : jamais la sécurité RDP standard, jamais TLS seule (écran de connexion graphique avant toute authentification). Une cible qui ne propose pas NLA est refusée (`RDP-E003`).

**Le compte de la ressource, jamais le secret dans le grant.** Le grant nomme le compte (format v2, ADR-0004), comme pour SSH. Le core envoie dans `session_params` le compte, le nom de la cible pour le SPN, l'empreinte épinglée ou la référence PKI, et le profil de cible (section 4). Le secret du compte est détenu par l'agent, jamais par le core ni le navigateur :

- **jalon M2, avant le coffre-fort** : un fichier par compte, référencé par `[agent.rdp] accounts_dir`, droits du service seul (même contrôle que `CFG-P008`), chargé dans un `Secret<…>` à l'usage et effacé après l'authentification. Pas de saisie du mot de passe dans le portail ;
- **ensuite** : le coffre-fort délivre le secret à l'agent pour une session (ADR-0009, section coffre-fort).

**Kerberos est la règle.** L'agent obtient un TGT pour le compte, puis un ticket de service pour `TERMSRV/<nom DNS de la cible>`, et les joue dans SPNEGO avec `package_list = "kerberos,!ntlm"` : `sspi` n'offre alors pas NTLM.

- **KDC configuré, jamais découvert** : `[agent.rdp.kerberos]` associe chaque domaine (realm) à ses KDC (`nom:88`). La découverte DNS de `sspi` n'est jamais appelée (`kdc_url` toujours fourni). Les adresses des KDC passent par le contrôle de périmètre (ADR-0005), comme celles des cibles.
- **Transport** : `sspi` rend la main à chaque requête réseau (générateur `NetworkRequest`) ; `ostena-rdp` la porte en **TCP** vers l'adresse épinglée, avec un délai de 5 s et une réponse bornée à 64 Kio. UDP et le proxy KDC HTTP sont refusés au jalon M2.
- **Chiffrement Kerberos** : AES256-CTS-HMAC-SHA1-96, puis AES128 ; `sspi` ne demande pas RC4-HMAC ni DES. Un KDC qui ne propose qu'un autre type est refusé (`RDP-E006`).
- **Cache de TGT** en mémoire de l'agent, par compte, jusqu'à 10 h ou la fin de vie du ticket : il évite deux allers-retours vers le KDC par session (section 4). Il est vidé à l'arrêt, à la rotation du secret et à tout échec d'authentification.
- **SPN** : `TERMSRV/` suivi du nom DNS de la cible tel qu'inscrit dans l'inventaire, distinct de l'adresse de connexion (épinglée). Une cible déclarée par sa seule adresse IP n'a pas de Kerberos.
- **CredSSP version 6 exigée** ([MS-CSSP], nonce du client, correctif de CVE-2018-0886). Une cible qui annonce moins est refusée (`RDP-E007`).

**Délégation du mot de passe ou Restricted Admin.** Deux modes, choisis par cible dans l'inventaire ; les réglages `[rdp]` de l'agent (ADR-0003) bornent ce qui est admis :

| Mode | Ce qui arrive sur la cible | Réglages ([rdp]) | Repli NTLM |
|---|---|---|---|
| Délégation | CredSSP `WithCredentials` : `TSPasswordCreds` chiffré pour la cible, qui ouvre une session avec ses propres identifiants réseau | `password_delegation = true` | **refusé en production** (`CFG-P003`, REG-SEC-02) |
| Restricted Admin | requête X.224 avec `RESTRICTED_ADMIN_MODE_REQUIRED` ([MS-RDPBCGR] 2.2.1.1.1), CredSSP `CredentialLess` : aucun secret transmis, la session n'a pas d'identifiants réseau | `password_delegation = false` | admis si `ntlm_fallback = true`, journalisé |

- **Restricted Admin est le mode recommandé** quand il est possible : le compte doit être administrateur de la cible, et la cible l'autoriser (`DisableRestrictedAdmin = 0`). L'agent vérifie que la réponse X.224 annonce `RESTRICTED_ADMIN_MODE_SUPPORTED` ; sinon il coupe avant CredSSP (`RDP-E008`), **sans retomber en délégation**.
- **Pourquoi NTLM est refusé avec délégation** : NTLM n'authentifie pas la cible par son nom. Un relais qui obtient une réponse NTLM valide recevrait le mot de passe délégué. En Restricted Admin, aucun mot de passe ne part : un compte local sur une cible hors domaine (cas de la CI, section 7) reste possible en production.
- **Repli NTLM, quand il est admis** : SPNEGO avec `package_list = "kerberos,ntlm"`, événement `rdp.ntlm_used` (journal et audit) à chaque session.
- **Remote Credential Guard** (`REDIRECTED_AUTHENTICATION_MODE_REQUIRED`) n'est pas proposé : il suppose que la cible renvoie ses demandes Kerberos au poste client, ce que l'agent ne sait pas servir.

### 3. Validation de la cible avant tout secret

La TLS vers la cible est construite par **`ostena-crypto::tls`** (rustls avec aws-lc-rs), jamais par IronRDP. Le certificat est validé **avant** CredSSP, donc avant tout envoi d'identifiant. Trois valeurs, déjà prévues par la configuration (`[rdp] certificate_validation`, ADR-0003) :

- **`pinned`** (défaut) : l'inventaire porte l'**empreinte SHA-256 du certificat DER** de la cible, transmise dans `session_params`. Un certificat différent est refusé (`RDP-E001`), avec l'empreinte présentée dans l'événement `rdp.certificate_mismatch` pour permettre de réépingler après vérification (`ostena target rdp-pin`, PR 7). La signature de la poignée de main reste vérifiée par rustls : l'épinglage remplace la chaîne, pas la preuve de possession de la clé.
- **`pki`** : chaîne vers `pki_ca_bundle` (l'autorité du client, jamais les racines publiques ni celles du système, déjà refusées par `deny.toml`), nom DNS de la cible dans le SAN, usage `serverAuth` ou l'usage « Remote Desktop Authentication » (OID 1.3.6.1.4.1.311.54.1.2), dates. Pas de contrôle de révocation au jalon M2 (limite connue).
- **`none`** : refusé en production (`CFG-P002`, REG-SEC-01), accepté en mode `development` avec l'événement `rdp.certificate_unchecked`.

Pas de confiance au premier contact en production. Les certificats auto-signés que Windows renouvelle seul changent de clé : en production, la PKI est préférable à l'épinglage au-delà de quelques cibles.

**Défense en profondeur** : avec Kerberos, CredSSP lie la clé publique TLS de la cible à la session (`pubKeyAuth`, [MS-CSSP]) et seule la vraie cible déchiffre le ticket de service. Un intermédiaire qui passerait la validation TLS échouerait donc encore à CredSSP. Ce n'est pas une raison d'alléger la validation TLS, qui protège aussi le mode NTLM et tout ce qui précède CredSSP.

**Clé publique pour CredSSP** : `sspi` attend le `subjectPublicKey` du certificat. Il est extrait du certificat validé par `ostena-crypto`, qui le rend avec le résultat de la vérification : `ostena-rdp` ne relit pas le certificat.

### 4. Séquence de connexion

La séquence suit [MS-RDPBCGR] 1.3.1.1 avec `ironrdp-connector`, encadrée par la garde de séquence :

1. **TCP** vers l'adresse épinglée par le contrôle de périmètre (ADR-0005).
2. **X.224** : requête avec `PROTOCOL_HYBRID_EX | PROTOCOL_HYBRID` et, en Restricted Admin, le drapeau ; cookie `mstshash` vide (le nom du compte ne passe pas en clair).
3. **TLS** (section 3), puis **CredSSP** (section 2) ; message *Early User Authorization Result* lu en `HYBRID_EX` : un refus coupe avant la session (`RDP-E009`).
4. **MCS Connect Initial avec GCC**, jonction des canaux, **licences**, **échange de capacités**, **finalisation**.

**`earlyCapabilityFlags` honorés** ([MS-RDPBCGR] 2.2.1.3.2). L'agent n'annonce que ce qu'il traite. La garde décode le bloc `TS_UD_CS_CORE` sortant et le compare à une table fermée « drapeau → module qui le traite » ; un drapeau hors table est retiré avant l'envoi et le test REG-RDP-03 échoue s'il apparaît. Table du jalon M2 :

| Drapeau | Traité par |
|---|---|
| `RNS_UD_CS_SUPPORT_ERRINFO_PDU` | boucle de session : code d'erreur traduit en raison de fin |
| `RNS_UD_CS_VALID_CONNECTION_TYPE` | type de connexion annoncé (`LAN`), cohérent avec l'auto-détection |
| `RNS_UD_CS_SUPPORT_NETCHAR_AUTODETECT` | répondeur Auto-Detect (ci-dessous) |
| `RNS_UD_CS_SUPPORT_DYNVC_GFX_PROTOCOL` | client EGFX en passthrough (section 5), annoncé seulement si le canal est enregistré |
| `RNS_UD_CS_STRONG_ASYMMETRIC_KEYS` | clé RSA de licence de toute taille acceptée (`ironrdp-pdu`) |
| `RNS_UD_CS_SUPPORT_SKIP_CHANNELJOIN` | jonction des canaux sautée si la cible l'accepte |
| `RNS_UD_CS_SUPPORT_MONITOR_LAYOUT_PDU` | disposition d'écrans transmise au navigateur |

Ne sont pas annoncés : `WANT_32BPP_SESSION` (sans objet en EGFX), `SUPPORT_STATUS_INFO_PDU`, `SUPPORT_HEARTBEAT_PDU` tant que le battement n'est pas traité, la souris relative, et tout canal que le grant n'autorise pas.

**Répondeur Auto-Detect** ([MS-RDPBCGR] 1.3.9, 2.2.14) : l'agent répond aux demandes de mesure d'aller-retour et de débit, à la connexion (dans le connecteur) et en continu (boucle de session), sans attendre le navigateur. La cible mesure donc le lien agent-cible, qui est celui qu'elle encode. Une demande inconnue est ignorée et comptée, jamais fatale (REG-RDP-04).

**Profil de cible mémorisé** (REG-PERF-01). Après chaque session réussie, l'agent renvoie au core, dans son bilan, un **profil** de la cible : version RDP, protocole de sécurité retenu, drapeaux de capacité précoce du serveur, canaux statiques acceptés et leurs identifiants MCS, prise en charge du saut de jonction, capacités EGFX confirmées, empreinte du certificat vu. Le core le conserve dans l'inventaire et le renvoie dans `session_params`. À la session suivante, l'agent :

- ne demande que les canaux que le grant autorise **et** que la cible a acceptés ;
- envoie toutes les jonctions en un seul lot quand la cible ne sait pas les sauter ;
- présente la licence conservée (ci-dessous) et le cache de TGT est déjà chaud ;
- compare le profil reçu au profil observé : un écart (mise à jour de la cible) est journalisé (`rdp.profile_changed`) et remplace l'ancien, sans échec.

Le profil n'est qu'une optimisation : un profil absent ou faux ralentit la connexion, jamais il ne l'autorise. Le nombre d'allers-retours de la séquence est compté et journalisé par phase (`rdp.connect_phases`).

**Licences RDS** (REG-RDP-06, [MS-RDPELE]). L'agent se présente avec un **nom de client et un identifiant matériel stables**, dérivés de l'identifiant de l'agent et de la cible (HMAC sous une clé de l'agent, pour ne pas révéler l'identifiant de l'agent), afin qu'une licence par appareil ne soit pas consommée à chaque session. La licence délivrée par la cible est conservée par le core (inventaire, par couple agent-cible) via le `LicenseCache` du connecteur, et présentée à la session suivante. Cas traités : licence valide immédiate (`STATUS_VALID_CLIENT`, mode d'administration à deux sessions), nouvelle licence, mise à niveau, défi de plateforme ; une erreur de licence (`ERR_INVALID_CLIENT`, pas de serveur de licences) est traduite en code `RDP-E010` avec le motif, sans boucle de réessai.

**Budget de la première image** (LAN, cible 2022, objectif p95 < 5 s), mesuré par phase dans la PR 7 puis de bout en bout dans la PR 13 :

| Phase | Budget |
|---|---|
| portail → grant → WebSocket → flux du tunnel | 300 ms |
| TCP, X.224, TLS 1.2 (quatre allers-retours) | 50 ms |
| Kerberos AS et TGS (0 avec le cache de TGT) | 100 ms |
| CredSSP (trois à quatre allers-retours) | 100 ms |
| MCS, licences, capacités, finalisation (profil et licence connus) | 150 ms |
| ouverture de session Windows (profil utilisateur) | 1 à 3 s, hors de notre contrôle |
| première trame EGFX, décodage, peinture | 200 ms |

L'ouverture de session Windows domine. Le reste doit tenir sous 1 s.

### 5. Passthrough EGFX vers le navigateur

**Principe** : l'agent ne décode pas l'image. Il reçoit les PDU EGFX ([MS-RDPEGFX]) sur le canal dynamique `Microsoft::Windows::RDS::Graphics`, les décompresse (ZGFX), les **valide** (décodeur strict, bornes) et les relaie **telles quelles** au navigateur dans `ostena-frame`. Le navigateur les décode.

**Capacités annoncées selon le navigateur.** Le navigateur annonce ce qu'il sait décoder **avant** l'ouverture de la session RDP (message de capacités d'`ostena-frame` v2, ci-dessous) : `VideoDecoder.isConfigSupported()` de WebCodecs pour les profils H.264 nécessaires à la taille demandée, avec `optimizeForLatency`. L'agent en déduit les `RDPGFX_CAPSET` qu'il annonce ([MS-RDPEGFX] 2.2.3) :

- **AVC420** : CAPVERSION 10.x sans `AVC_DISABLED`, cache réduit (`SMALL_CACHE`). C'est le mode par défaut ;
- **AVC444** (et AVC444v2) : seulement si le navigateur le déclare et que l'inventaire l'autorise pour la cible. Il demande deux décodeurs H.264 et une recombinaison des plans de chrominance par un *shader* WebGL, soit 2 à 4 ms de plus par image (à mesurer dans la PR 13) ; il est réservé aux usages où la netteté du texte prime ;
- **repli tuiles** : si le navigateur ne décode pas H.264, l'agent annonce les versions sans AVC (`AVC_DISABLED`, ou 8.1 sans AVC420). La cible envoie alors Planar, ClearCodec, RemoteFX progressif, remplissages et copies, décodés dans le navigateur par `ironrdp-graphics` compilé en WebAssembly (`ostena-web-client`). L'agent reste en passthrough dans les deux modes.

Les capacités ne changent pas en cours de session ; un navigateur qui se reconnecte avec d'autres capacités ouvre une nouvelle session RDP.

**Ce que l'agent traite lui-même** : l'annonce et la confirmation des capacités, le refus de l'offre d'import de cache (aucun cache persistant), et la validation. **Ce qu'il relaie** : tout le reste, dans les deux sens. Les `RDPGFX_FRAME_ACKNOWLEDGE_PDU` ([MS-RDPEGFX] 2.2.2.13) viennent **du navigateur**, après décodage : la cible règle son débit sur ce que le navigateur absorbe réellement, et aucune file ne gonfle dans l'agent ou le core. Si le navigateur ne répond plus, la cible s'arrête d'elle-même ; l'agent n'acquitte jamais à sa place.

**Validation par l'agent**, avant tout relais (protège le navigateur et l'enregistreur) : PDU complète et bien formée, identifiants de surface connus, au plus 16 surfaces, surfaces de 8192 × 8192 au plus, rectangles inclus dans leur surface, PDU de 4 Mio au plus après décompression, flux AVC420/AVC444 conformes à [MS-RDPEGFX] 2.2.4.4 à 2.2.4.6 (métablocs, longueurs). Une PDU refusée coupe la session (`RDP-E020`).

**Extension d'`ostena-frame` (version 2, PR 13).** L'en-tête ne change pas (ADR-0006). La v2 ajoute :

- un message de **capacités de décodage** du navigateur (profils H.264, AVC444, WebAssembly), avant la session ;
- un type **PDU graphique** (passerelle → navigateur, fragmentable, réassemblage borné à 4 Mio) qui porte une PDU EGFX décompressée et validée ;
- un type **acquittement graphique** (navigateur → passerelle) qui porte le `FRAME_ACKNOWLEDGE` ou le `QOE_FRAME_ACKNOWLEDGE` du navigateur ;
- l'ordonnanceur garde sa priorité stricte : contrôle > entrées > audit > données en masse.

**Priorité des entrées.** Les entrées du navigateur (clavier, souris, tactile) voyagent sur le flux **interactif** du tunnel (priorité 30) et sont écrites vers la cible en fast-path dès réception, par une tâche d'écriture qui ne passe jamais derrière une écriture d'affichage. Les mouvements de souris en attente sont fusionnés (ADR-0006). Le navigateur traduit `KeyboardEvent.code` en *scancodes* ; la resynchronisation des verrous (`TS_SYNC_EVENT`) suit le focus. Le changement de taille passe par [MS-RDPEDISP].

**Budget de latence ajoutée** (p99, hors propagation réseau, LAN de référence) :

| Étape | Budget |
|---|---|
| agent : TLS, démultiplexage, ZGFX, validation, trame | 0,5 ms |
| tunnel QUIC et relais du core, WebSocket TLS | 1,5 ms |
| navigateur : réassemblage, WebCodecs (décodage matériel), peinture | 8 ms |

**Mesure** (banc de la PR 13) : l'agent date l'arrivée de la PDU `EndFrame` de chaque trame, le navigateur date sa peinture (`requestVideoFrameCallback` ou fin du dessin WebGL) ; la latence ajoutée est la différence, moins la moitié de l'aller-retour agent-navigateur mesuré par Ping et Pong. Le banc est affiché en CI sans seuil bloquant au jalon M2 (« fonctionnel »), comme les autres bancs.

### 6. Enregistrement : écrit par le core, à partir du flux relayé

Le navigateur reçoit l'image **au travers du core** (ADR-0020). Le core enregistre donc **ce qu'il relaie** : chaque PDU graphique est remise à l'enregistreur avant d'être écrite sur la WebSocket. On ne double pas le flux vidéo sur le tunnel (un flux `Recording` séparé, comme pour SSH, doublerait de 1 à 10 Mbit/s par session le lien montant de l'agent), et ce qui est enregistré est, par construction, ce que l'utilisateur a vu.

- **Échec fermé**, comme l'ADR-0016 : une PDU n'est jamais relayée au navigateur sans avoir été remise à la file de l'enregistreur ; un enregistrement impossible coupe la session.
- **Format** (détaillé par l'ADR-0023, PR 14) : MKV écrit par le core de façon déterministe (`ostena-recorder`, écrivain EBML sans dépendance). Une piste vidéo H.264 par surface, **le flux AVC tel quel** (pour AVC444, le flux principal, lisible par les lecteurs courants) ; une piste privée pour ce qui n'est pas du H.264 standard (flux auxiliaire AVC444, PDU de tuiles, remplissages, copies, caches, changements de taille), pour un rejeu exact par le lecteur du portail, qui réutilise le décodeur du navigateur. Une session en repli tuiles est donc enregistrée aussi, dans la piste privée. Pas de frappes au clavier au jalon M2, comme pour SSH.
- **Scellement** : comme l'ADR-0016. Fichier synchronisé puis passé en lecture seule, SHA-256, taille, nombre de trames, raison de fin, écrits dans la ligne d'enregistrement et dans l'enregistrement d'audit `recording.sealed` d'une même transaction ; vérification hors ligne par `ostena audit verify --recordings` (REG-RDP-07).
- **Accès RDP natif** (hors jalon) : le flux ne passant plus par le core, l'agent enverra le même flux de PDU sur un flux `Recording` (ADR-0016), et le core écrira le même format.

### 7. Tests sans laboratoire

**Serveur de test IronRDP, en CI Linux.** `crates/ostena-rdp/tests/support/` construit un petit serveur sur `ironrdp-acceptor` 0.12.0 (dépendance de développement) : X.224, TLS (certificat de test émis par `ostena-crypto::pki`), CredSSP côté serveur par `sspi` (NTLM ; Kerberos si le serveur `sspi` le permet, à vérifier dans la PR 7), MCS, licences, capacités, puis des PDU EGFX scénarisées. Les flux H.264 de test sont **générés par nos tests** : un encodeur minimal en macroblocs I_PCM (SPS, PPS, tranche IDR, données brutes), sans bibliothèque, décodable par WebCodecs et par les lecteurs. Aucune capture de trafic d'un produit tiers. Ce serveur peut mal se comporter sur commande : certificat autre, version CredSSP 5, NLA absente, Restricted Admin non supporté, `earlyCapabilityFlags` inattendus, auto-détection, erreurs de licence, PDU EGFX hors bornes.

**Cible Windows réelle, sur les exécuteurs Windows de GitHub** (Windows Server 2022 et 2025 ; 2016 et 2019 sur le laboratoire de démonstration). Le job active le Bureau à distance (`fDenyTSConnections = 0`, NLA exigée), autorise le Restricted Admin (`DisableRestrictedAdmin = 0`), crée un compte local administrateur au mot de passe tiré dans le job, lit l'empreinte SHA-256 du certificat RDP de la machine, et connecte l'agent sur la boucle locale. Hors domaine, donc sans Kerberos :

- **mode `production`** : Restricted Admin avec NTLM et certificat épinglé, ce que la production admet (aucun mot de passe délégué) ; vérifie aussi REG-SEC-01 (empreinte fausse refusée) et REG-SEC-02 (délégation avec NTLM refusée à la validation de la configuration) ;
- **mode `development`** (le « mode test ») : délégation du mot de passe avec NTLM, refusée en production, pour exercer `WithCredentials` ;
- mesures : durée par phase de la séquence, première trame EGFX (H.264 logiciel imposé par la stratégie locale), jusqu'à la première image dans le navigateur avec la PR 13.

Kerberos de bout en bout est validé sur le laboratoire (domaine Active Directory), et en CI par le serveur de test si `sspi` sait jouer le rôle de serveur Kerberos ; sinon, par un KDC open source empaqueté par la distribution sur l'exécuteur Linux, contre lequel seul le client Kerberos est testé (TGT, ticket de service, refus des types de chiffrement hors liste).

**Cibles de fuzz côté client** (dans `fuzz/`, corpus rejoués sur la toolchain stable, campagne de 72 h cumulées par cible avec la PR 19) :

| Cible | Analyseur | PR |
|---|---|---|
| `rdp_x224` | confirmation X.224, réponse de négociation, échec | 7 |
| `rdp_mcs_gcc` | MCS Connect Response, blocs GCC du serveur, jonctions | 7 |
| `rdp_tsrequest` | `TSRequest` DER, jetons SPNEGO, réponses KDC (AS-REP, TGS-REP, KRB-ERROR) | 7 |
| `rdp_license` | PDU de licence : demande, défi de plateforme, licence nouvelle ou mise à niveau | 7 |
| `rdp_session` | démultiplexage fast-path et slow-path, auto-détection, informations d'erreur | 7 |
| `rdp_drdynvc` | PDU DRDYNVC, fragmentation et réassemblage | 13 |
| `rdp_egfx` | ZGFX puis PDU EGFX et validation de l'agent | 13 |
| `rdp_cliprdr` | PDU CLIPRDR | 17 |
| `rdp_rdpdr` | PDU RDPDR et requêtes d'entrées-sorties | 17 |

Les cibles vérifient aussi qu'aucune entrée ne fait paniquer : les `unwrap()` repérés dans `sspi` sur des réponses du KDC en sont le premier cas. En attendant le correctif amont, une panique dans une dépendance est contenue à la tâche de la session (le profil de release garde le déroulement de pile) : la session est coupée (`RDP-E099`), l'agent continue. La compilation d'IronRDP et de `sspi` avec le nightly épinglé du fuzz est à vérifier dans la PR 7 (russh ne compile pas avec lui, ADR-0009).

**Tests de non-régression nommés** :

| Nom | Comportement vérifié | PR |
|---|---|---|
| `REG-SEC-01` | certificat de cible différent de l'empreinte, ou hors PKI : refus avant tout identifiant ; `none` refusé en production | 7 |
| `REG-SEC-02` | délégation du mot de passe sans Kerberos : aucun repli NTLM, refus ; configuration refusée en production | 7 |
| `REG-RDP-03` | pas de coupure après 60 s : seuls les `earlyCapabilityFlags` de la table sont annoncés, chacun avec son module (saut de jonction des canaux annoncé seulement s'il est honoré) ; session de 2 h sans coupure | 7 |
| `REG-RDP-04` | téléchargement depuis le lecteur redirigé jamais figé : demandes Auto-Detect de connexion et continues servies sans blocage ; 1 Go à un débit conforme au lien | 7, 17 |
| `REG-RDP-06` | licence obtenue puis représentée à la session suivante, nom et identifiant de client stables, erreurs traduites | 7 |
| `REG-PERF-01` | profil de cible mémorisé : moins d'allers-retours à la seconde connexion, écart de profil détecté | 7 |
| `REG-RDP-01` | transfert massif par le canal disque avec une passerelle Windows : copie de 5 Go sans erreur (gestion des tampons de sécurité de CredSSP et du chiffrement sur de longs flux) | 17 |
| `REG-RDP-02` | traits d'un pixel en RLE 16 bpp : rejeu d'une capture dans le repli tuiles, comparaison pixel à pixel avec la référence | 13 |
| `REG-RDP-05` | sous-dossier accessible malgré des erreurs : les réponses RDPDR d'erreur portent tous leurs champs (dont `Length`) ; navigation dans une arborescence avec erreurs provoquées (droits, fichiers verrouillés) ; canaux et périphériques non autorisés refusés et journalisés | 17 |
| `REG-RDP-07` | enregistrement jamais noir en passthrough EGFX : sessions AVC420 et AVC444 enregistrées, images non vides et conformes, MKV lisible, scellé, toute modification détectée hors ligne | 14 |

### 8. Découpage de la mise en œuvre

- **PR 7 `m2/rdp-driver`** : crate `ostena-rdp` (sans base ni API) ; dépendances et `deny.toml` (doublons, enveloppes des crates cryptographiques, section « Écart » ci-dessous) ; profil TLS cible et vérificateurs `pinned` et `pki` dans `ostena-crypto` ; CredSSP piloté (Kerberos, transport KDC, NTLM selon la règle, Restricted Admin, version 6) ; garde de séquence ; licences et profil de cible portés par `session_params` et le bilan ; boucle de session sans image ; implémentation du trait `Driver` (ADR-0018) ; codes `RDP-E0xx` et événements ; serveur de test et job Windows ; fuzz X.224, MCS/GCC, TSRequest, licences, session ; `REG-SEC-01`, `REG-SEC-02`, `REG-RDP-03`, `REG-RDP-04`, `REG-RDP-06`, `REG-PERF-01`.
- **PR 13 `m2/rdp-egfx`** : DRDYNVC et client EGFX en passthrough, `ostena-frame` v2, décodage WebCodecs AVC420 puis AVC444, repli tuiles en WebAssembly, acquittements de bout en bout, entrées prioritaires, changement de taille ; fuzz EGFX et DRDYNVC ; banc de latence navigateur et mesure de la première image ; `REG-RDP-02`.
- **PR 14 `m2/rdp-recording`** (ADR-0023) : écrivain MKV du core, scellement, vérification hors ligne, lecteur du portail ; `REG-RDP-07`.
- **PR 17 `m2/rdp-channels`** : CLIPRDR et RDPDR (lecteurs seulement) soumis aux droits du grant ; fuzz CLIPRDR et RDPDR ; `REG-RDP-01`, `REG-RDP-05` (et `REG-RDP-04` pour le débit du lecteur redirigé).

### Écart cryptographique à ajouter à l'ADR-0009 (proposé)

Comme russh pour SSH, IronRDP et `sspi` apportent leur propre cryptographie, et le protocole en impose une partie hors de la liste figée :

| Usage | Mécanismes | Implémentation |
|---|---|---|
| Kerberos | AES256/128-CTS-HMAC-SHA1-96, PBKDF2-HMAC-SHA1 | `picky-krb` (RustCrypto) |
| NTLM, quand il est admis | MD4, MD5, HMAC-MD5, RC4 | `sspi` (RustCrypto, RC4 propre) |
| CredSSP v6 | SHA-256 (hachage du nonce), chiffrement GSS de Kerberos ou NTLM | `sspi` |
| Licences [MS-RDPELE] | RSA brut (sans bourrage, `num-bigint`, pas en temps constant), RC4, MD5, SHA-1 | `ironrdp-pdu` |
| Présents mais non utilisés | DES3 (Kerberos), RC2, AES-KW, Ed25519, X25519, P-384, P-521, RSA de `picky` | `picky`, `picky-krb` |
| TLS vers la cible | voir ci-dessous | `ostena-crypto` (aws-lc-rs) |

- **Confinement** : ces crates ne sont dépendances que d'`ostena-rdp` (et, pour les PDU et les décodeurs d'image sans cryptographie, d'`ostena-web-client`). `deny.toml` les enveloppe comme celles de russh ; `des`, aujourd'hui interdite partout, n'est admise que par `picky` et `picky-krb`.
- **Portée** : ces mécanismes ne protègent que le segment agent-cible, à l'intérieur de la TLS validée (section 3), et seulement parce que Windows les impose. Le secret des licences ne protège qu'une licence.
- **TLS vers la cible** : le profil figé du tunnel (TLS 1.3, `SecP256r1MLKEM768` seul) est inapplicable aux cibles Windows, qui ne proposent pas ML-KEM et, pour 2016 et 2019, pas TLS 1.3 pour RDP. Profil proposé : TLS 1.3 quand la cible le propose, sinon TLS 1.2 avec *extended master secret* ; suites ECDHE avec AES-256-GCM seulement ; groupes P-256 et P-384 ; certificats RSA d'au moins 2048 bits ou ECDSA P-256. Cela demande la fonctionnalité `tls12` de rustls, dans `ostena-crypto` seulement, pour ce seul profil.

### 9. Mise en œuvre (PR 7) : codes, événements et écarts

**Codes et événements** (`ostena_rdp::RdpError`, stables) :

| Code | Cas | Événement |
|---|---|---|
| `RDP-E001` | certificat refusé (empreinte, hors PKI), avant tout identifiant | `rdp.certificate_mismatch` |
| `RDP-E002` | cible injoignable ou connexion fermée | `rdp.target_unreachable` |
| `RDP-E003` | pas de NLA proposée | `rdp.target_refused` |
| `RDP-E004` | négociation TLS impossible | `rdp.target_refused` |
| `RDP-E005` | CredSSP refusé | `rdp.target_auth_failed` |
| `RDP-E006` | Kerberos impossible (KDC absent, injoignable, refus) | `rdp.target_auth_failed` |
| `RDP-E007` | CredSSP antérieur à la version 6 | `rdp.target_refused` |
| `RDP-E008` | Restricted Admin exigé, non annoncé | `rdp.target_refused` |
| `RDP-E009` | refus après CredSSP (*Early User Authorization*) | `rdp.target_auth_failed` |
| `RDP-E010` | licence RDS refusée | `rdp.license_failed` |
| `RDP-E011` | NTLM là où il n'est pas admis | `rdp.target_auth_failed` |
| `RDP-E012` | séquence invalide | `rdp.target_refused` |
| `RDP-E013` | redirection demandée | `rdp.target_refused` |
| `RDP-E014` | fin de session avec un code d'erreur de la cible | `rdp.session_error` |
| `RDP-E015` | délai d'établissement dépassé | `rdp.target_unreachable` |
| `RDP-E016` | secret du compte illisible sur l'agent | `rdp.target_auth_failed` |
| `RDP-E017` | `session_params` invalides | `rdp.params_refused` |
| `RDP-E018` | session du même compte tenue par une autre connexion (ADR-0026) | `rdp.session_in_use` |
| `RDP-E019` | sessions Windows du compte impossibles à fermer (ADR-0026) | `rdp.session_cleanup_failed` |
| `RDP-E021` | canal de gestion des sessions refusé : nom DNS absent ou qui ne résout pas vers l'adresse épinglée (ADR-0026) | `rdp.session_channel_refused` |
| `RDP-E022` | Kerberos impossible sur le canal de gestion, NTLM refusé (ADR-0026) | `rdp.session_channel_ntlm_refused` |
| `RDP-E023` | la cible n'exige pas la signature SMB, en production (ADR-0026) | `rdp.smb_signing_refused` |
| `RDP-E099` | panique d'une dépendance, session coupée | `rdp.internal_error` |

Événements de succès : `rdp.connect_phases` (durée et allers-retours par phase : `tcp`, `x224`, `tls`, `credssp`, `mcs`, `licensing`, `activation`), `rdp.ntlm_used`, `rdp.profile_changed`, et depuis l'ADR-0026 `rdp.session_logged_off`, `rdp.session_cleanup_skipped`, `rdp.session_channel_ntlm` et `rdp.smb_signing_not_required` (avertissements du développement), `rdp.session_closed` (debug, raison d'une fermeture vue par le transport).

**Fin de session (ADR-0026)** : la session Windows est fermée par l'agent (API WTS), jamais laissée déconnectée ; les sessions du compte laissées sur la cible sont fermées avant une nouvelle session, ou la session est refusée.

**Écarts et précisions par rapport aux sections 2 à 7**, constatés pendant la mise en œuvre :

- **Mot de passe hors du connecteur** : le connecteur reçoit le nom du compte et un mot de passe vide ; seul CredSSP (piloté par l'agent) porte le secret. Le *Client Info PDU* ne contient donc jamais de mot de passe.
- **Phase des licences** : la première PDU de licence peut arriver alors que le connecteur attend encore l'auto-détection de connexion ; la phase est donc déterminée par la PDU (`SEC_LICENSE_PKT`), pour la mesure comme pour la traduction d'erreur en `RDP-E010`.
- **Mode `pki`** : le vérificateur exige l'usage `serverAuth`. Un certificat qui ne porterait que l'usage « Remote Desktop Authentication » (1.3.6.1.4.1.311.54.1.2) est refusé : les certificats émis par une autorité d'entreprise pour RDP portent en pratique les deux. À revoir si un client en présente un sans `serverAuth`.
- **`certificate_validation = "none"`** n'est pas offert par le driver : le mode de développement utilise aussi une empreinte épinglée (lue sur la cible par le job Windows).
- **Cache de TGT** : non réalisé, `sspi` 0.23.0 n'offrant pas d'API pour injecter ou récupérer un ticket (correctif amont proposé, `docs/notes/ironrdp-sspi-correctifs-amont.md`). Coût : deux allers-retours vers le KDC par session Kerberos.
- **Une seule adresse tentée** : les paramètres d'authentification (et le secret) sont consommés par la tentative ; l'agent ne rejoue pas CredSSP sur une deuxième adresse de la même cible.
- **Serveur de test** : CredSSP côté serveur en SPNEGO avec NTLM seulement. Kerberos de bout en bout reste à valider sur le laboratoire ; en CI, le refus de tout repli NTLM quand seul Kerberos est admis (REG-SEC-02) est vérifié contre ce serveur. Le chemin « nouvelle licence » n'est pas exercé (le serveur de test, comme une cible Windows sans rôle RDS, répond `STATUS_VALID_CLIENT`) ; la conservation et la présentation de la licence sont couvertes par des tests unitaires du cache.
- **Désactivation-réactivation** : traitée par la boucle de session (séquence d'activation du connecteur rejouée), sans test de bout en bout à ce stade.
- **Cibles de fuzz** : `rdp_tsrequest` ne couvre pas encore les réponses du KDC. `sspi` 0.23.0 panique sur une liste vide de types de chiffrement (signalé en amont) et le fuzzer la trouverait aussitôt ; elles entreront dans la cible avec le correctif. Les graines sont les PDU que le serveur de test envoie en clair sur six scénarios (fin de session, auto-détection, information d'erreur, licence refusée, accès refusé, Restricted Admin), régénérables par un test ignoré. `ostena_rdp::fuzz` porte les points d'entrée : le crate de fuzz n'atteint IronRDP et `sspi` que par `ostena-rdp`, comme le veulent les enveloppes de `deny.toml`. IronRDP et `sspi` compilent avec le nightly épinglé du fuzz (vérifié).
- **Job Windows (`rdp-windows`)** : script `tests/rdp/windows-target.ps1`, puis `tests/windows_target.rs`, une session à la fois. REG-SEC-01 (empreinte fausse refusée à la TLS) et REG-SEC-02 (délégation avec NTLM refusée en production, avant toute connexion) y sont vérifiés au niveau du driver ; le refus à la validation de la configuration viendra avec la section de configuration RDP de l'agent. Le test échoue si la session n'est pas établie en moins de 5 s ; les phases mesurées vont au résumé du job.

**Mesures de la PR 7** (2026-11-26) :

- **Établissement contre une vraie cible Windows** (job `rdp-windows`, exécuteurs GitHub, boucle locale, compte local, NTLM, sans domaine), du `connect` du driver jusqu'à la fin de l'activation :

  | Cible | Restricted Admin (production) | Délégation (développement) |
  |---|---:|---:|
  | Windows Server 2025 | 112 ms | 326 ms |
  | Windows Server 2022 | 124 ms | 466 ms |

  L'activation, où Windows ouvre la session, domine : 80 à 240 ms. En Restricted Admin, le reste de la séquence prend moins de 10 ms. La délégation passe en premier dans le job : c'est la première connexion après le démarrage du service, et elle paie 125 à 150 ms d'attente de la confirmation X.224. La séquence compte 13 à 14 allers-retours : TCP 1, X.224 1, TLS 2, CredSSP 4, MCS 3 à 4, activation 2. Sur la boucle locale, ils ne coûtent presque rien ; avec 10 ms de latence vers la cible, ils ajouteraient environ 140 ms. Après la correction de la détection des PDU de licence, qui faisait apparaître une phase `licensing` fantôme, une deuxième exécution donne des totaux du même ordre : 120 et 278 ms sur 2025, 130 et 459 ms sur 2022. La PDU de licence de Windows arrive pendant que le connecteur attend l'auto-détection : son attente est comptée dans la phase `mcs`, et `licensing` reste à 0 ms.
- **Mémoire par session côté agent** : environ **40 Kio** de mémoire résidente par session. Mesure sous Linux, en release, avec 20 sessions tenues sans image ; le serveur de test tourne dans un autre processus (test `footprint`, à la demande). C'est un ordre de grandeur bas : l'allocateur réutilise la mémoire libérée par la première session, et les tampons EGFX de la PR 13 viendront s'y ajouter.
- **Empreinte du binaire** : **+2 533 280 octets (+2,42 Mio)** sur le binaire `ostena` de release pour Linux (12 352 752 → 14 886 032 octets), soit +20,5 %. Mesure faite en liant temporairement à `ostena-cli` la séquence de connexion et la boucle de session (`establish` et `SessionLoop::run`), avec le profil de release actuel (`opt-level = "s"` pour `ostena-rdp` et IronRDP). Le chiffre est dans l'estimation de la section « Empreinte » (2 à 2,8 Mo). Le driver n'est pas encore lié au binaire : `xtask footprint` ne bouge donc pas avec cette PR, et la décision explicite sur l'empreinte reste à prendre au raccordement à l'agent.
- **Première image** : sans objet tant que la PR 13 n'a pas apporté l'EGFX.

**Avis `RUSTSEC-2023-0071` (attaque Marvin) ignoré, décision du responsable du projet du 2026-11-26.** L'avis vise `rsa` 0.10.0-rc.18, tirée sans option par `picky`, `sspi` et `winscard` aux versions épinglées ; aucune version corrigée n'existe. L'attaque est un canal auxiliaire temporel sur les opérations RSA **à clé privée** (déchiffrement, signature) : il faut un oracle chez la victime. L'agent n'en fait aucune : les licences RDS sont chiffrées avec la clé publique de la cible, les signatures ne sont que vérifiées avec des clés publiques, Kerberos (AES) et NTLM n'emploient pas RSA, PKINIT, PKU2U et la carte à puce ne sont jamais construits, et la TLS vers la cible passe par rustls et aws-lc-rs. L'exception figure dans `deny.toml` avec cette raison, la référence à cette section et une date de réexamen : **2027-03-31**, ou plus tôt à toute montée d'IronRDP ou de `sspi`. Contrôles : `ostena-rdp` ne dépend pas de `rsa` (enveloppes de `deny.toml`), et le test `no_rsa_private_key_in_ostena_rdp` échoue si le code de la crate nomme un type ou un chemin qui construit ou emploie une clé privée (identité de carte à puce, PKINIT, PKU2U, clé privée de `picky` ou de `rsa`).

## Conséquences

- L'agent ouvre des sessions RDP authentifiées par Kerberos sans qu'aucun secret ne traverse le grant, le core ou le navigateur ; le Restricted Admin évite même d'en envoyer un à la cible.
- L'agent ne décode aucune image : faible coût CPU, pas de tampon d'image, latence de l'agent bornée par la validation. Le décodage et sa variabilité sont dans le navigateur ; un navigateur sans décodage H.264 matériel paie plus cher, ou tombe en tuiles.
- Le core devient l'enregistreur des sessions RDP par navigateur et porte la charge d'écriture des vidéos.
- Environ 65 crates de plus, deux versions préliminaires ou figées (`picky` rc, tout IronRDP en `=`), du code natif (`libz-sys`) et `dlopen` importé tant que le correctif amont `scard` n'est pas accepté. Les montées de version d'IronRDP seront fréquentes et cassantes.
- L'empreinte du binaire augmente de 2 à 2,8 Mo : décision explicite attendue avec la mesure de la PR 7.
- L'évaluateur CSPN devra examiner un deuxième écart cryptographique, plus large que celui de SSH, imposé par le protocole.

### Limites connues

- Pas de contrôle de révocation des certificats en mode `pki` au jalon M2.
- Kerberos exige le nom DNS de la cible et une horloge de l'agent à moins de 5 minutes de celle du KDC ; une cible connue par son adresse seule n'a que le Restricted Admin avec NTLM.
- Les mots de passe des comptes de ressource sont sur le disque de l'agent, protégés par les droits du fichier, jusqu'au coffre-fort.
- AVC444 coûte plus cher dans le navigateur ; s'il dépasse le budget de latence, il reste en option.
- Le repli tuiles décode dans le navigateur des codecs plus lourds (RemoteFX progressif) : à mesurer avant d'en garantir la latence.
- Windows Server 2016 et 2019 ne sont testés que sur le laboratoire.

### Points à trancher (responsable du projet)

1. **Écart cryptographique RDP** dans l'ADR-0009 (tableau ci-dessus), avec l'admission de `des` par `picky` et `picky-krb`.
2. **Profil TLS vers les cibles** (TLS 1.2 admis, ECDHE sans ML-KEM, RSA 2048).
3. **Secrets des comptes de ressource sur l'agent** avant le coffre-fort (fichier protégé par les droits, comme la clé SSH de l'agent), ou attente du coffre-fort pour la délégation et le Restricted Admin seulement avec des comptes dont le secret est géré autrement.
4. **Écart d'empreinte** du binaire, une fois remesuré dans la PR 7.
