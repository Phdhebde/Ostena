# ADR-0009 : Choix cryptographiques et conformité aux guides ANSSI

- **Statut** : Accepté
- **Date** : 2026-11-11
- **Révision** : 2026-11-11, algorithmes du coffre-fort décidés (P-256 + ML-KEM-768, ECDSA P-256 + ML-DSA-65)
- **Révision** : 2026-11-13, écart SSH : cryptographie de russh dans `ostena-ssh`
- **Révision** : 2026-11-25, engagements de la PR 6 : chargement différé d'`oleaut32`, contrôles des imports et des modules chargés, remesure de l'empreinte ; écart d'empreinte accepté par le responsable du projet
- **Révision** : 2026-11-25, profil de release compilé en taille, chemin chaud gardé à `opt-level = 3` (PR 6bis)

## Contexte

CLAUDE.md impose des algorithmes figés selon les guides ANSSI, non négociables. Ce choix doit être vérifié dans les versions en vigueur des guides, et l'arbitrage consigné, pour un futur dossier CSPN. Il couvre :
- les grants de session (ADR-0004) ;
- le tunnel mTLS entre l'agent et le core (ADR-0008, à venir) ;
- la transition post-quantique.

Références consultées le 2026-11-11 :

- **[PG-083]** ANSSI-PG-083 v3.00 du 2026-03-20, « Règles et recommandations concernant le choix et le dimensionnement des mécanismes cryptographiques ». Elle remplace la v2.04 de 2020 et prend en compte la menace quantique. Il n'existe pas d'annexe post-quantique séparée : les règles post-quantiques (`RègPQ…`, `RecoPQ…`) sont dans le corps du guide.
- **[PA-079]** ANSSI-PA-079 v1.0 (2021), « Guide de sélection d'algorithmes cryptographiques ». La page de l'ANSSI le présente toujours comme en vigueur, à côté de la v3.00 du PG-083.

## Décision

### Position des guides par mécanisme

| Mécanisme | [PG-083] v3.00 | [PA-079] | Verdict |
|---|---|---|---|
| **ECDSA P-256** | conforme : P-256 est dans les « mécanismes conformes » du § 2.2.1.2 (`RègleCourbeElliptiqueGFp`), et ECDSA FIPS 186-5 sur P-256 dans ceux du § 2.2.3 (`RecoSignature`) | recommandé : R18 (§ 5.3, NIST P-256) et R21 (§ 6.2, EC-DSA) | ✅ retenu (certificats du tunnel, grants) |
| **ML-KEM-768** | conforme **s'il est hybridé** avec un mécanisme classique (§ 2.2.2, `RecoConfidentialitéAsym`) ; « il est toutefois préférable » d'utiliser ML-KEM-768 plutôt que ML-KEM-512 ; seul, il n'est pas conforme (`RègleSécuAsym`). Le paramétrage répond à `RèglePQRéseauEuclidien` (§ 2.2.1.3) | R19 (§ 5.4) : ne pas employer seul un schéma post-quantique, le combiner avec une primitive éprouvée | ✅ retenu en hybride |
| **Hybridation d'un KEM** | « méthode la plus souhaitable » : un KEM classique et un KEM post-quantique, combinés par une fonction de dérivation de clés (§ 2.2, « Modes d'hybridation conformes » ; `RègleSécuAsym` et `RèglePQSécuAsym`) | R19 | ✅ c'est la construction de `SecP256r1MLKEM768` dans TLS 1.3 |
| **X25519 (Curve25519)** | absente des « mécanismes conformes » du § 2.2.1.2, qui ne citent que FRP256v1, P-256/384/521 et brainpool ; elle respecte cependant `RègleCourbeElliptiqueGFp` (sous-groupe premier de 253 bits) | recommandée : R18 (§ 5.3, note 5.3.b) | ⚠️ défendable, mais plus citée par la v3.00 : **écartée** |
| **Ed25519 (EdDSA)** | absent : seuls RSA-SSA-PSS, ECDSA, ECKCDSA, SLH-DSA, et ML-DSA en hybride sont cités (§ 2.2.3) | absent de la table de R21 (§ 6.2), qui cite EC-DSA, EC-KCDSA, EC-GDSA, EC-SDSA et EC-FDSA | ❌ **écarté** |
| **AES-256-GCM** | AES-GCM conforme (§ 2.1.2.1) ; si une sécurité post-quantique est visée, clés d'au moins 192 bits recommandées (§ 2.1.1, `RecoPQTailleCléSym`) | R12 (§ 4.5, GCM) | ✅ retenu ; AES-128 écarté |
| **SHA-384 et SHA-256** | si une sécurité post-quantique est visée, empreintes d'au moins 384 bits recommandées (§ 2.1.4, `RecoPQHachage`) ; 256 bits « présumé suffisant » | R3 (§ 3.3, SHA-2 d'au moins 256 bits) | ✅ SHA-384 pour TLS ; SHA-256 pour les signatures P-256 |
| **Confidentialité persistante** | `RecoConfidentialitéPersistante` et `RecoPQConfidentialitéPersistante` (§ 2.2.4) | — | ✅ échange de clés éphémère hybride, sans clé pré-partagée |
| **Calendrier** | `RecoSécuLongTerme` (§ 2) : viser une sécurité post-quantique pour tout usage au-delà du 1er janvier 2030 ou en cas de risque d'attaque rétroactive ; pour les produits à longue durée de vie, mécanismes d'authentification post-quantiques « dès à présent » (encadré « Information ») | annexe A.3 : solutions hybrides pour protéger des informations au-delà de 2030 | ⚠️ voir le risque accepté |

### Choix figés

**Grants** (ADR-0004) :
- ECDSA P-256 / SHA-256, valeur d'algorithme 2 ; toute autre valeur est refusée, dont 1 (Ed25519, premier projet) ;
- signature brute `r ‖ s` de 64 octets, forme low-S imposée, vérification stricte (`r` et `s` dans `[1, n − 1]`, `s ≤ (n − 1)/2`, clé publique sur la courbe) ;
- kid = 8 premiers octets du SHA-256 de la clé publique SEC1 non compressée.

L'encadré « Attention » du § 2.2.3 rappelle qu'ECDSA n'est pas fortement résistant à la contrefaçon (une signature est malléable). L'anti-rejeu repose sur le jti, pas sur les octets de la signature, et la forme low-S est imposée en plus.

**Tunnel mTLS** (ADR-0008) :
- TLS 1.3 seul ;
- suite `TLS_AES_256_GCM_SHA384` seule ;
- groupe d'échange de clés `SecP256r1MLKEM768` seul : une poignée de main qui ne le négocie pas échoue, avec un code `TUN` dédié ;
- certificats ECDSA P-256 / SHA-256 pour la CA du core et pour les agents. P-256 garde ouverte une clé d'agent non exportable dans un TPM 2.0 (qui ne gère pas Ed25519) et la CA dans un HSM.

**Aléa et dérivation** :
- aléa du système d'exploitation via `aws-lc-rs` ;
- HKDF-SHA-256 (déjà dans `ostena-crypto`).

**Scellement de la clé racine hors ligne** (`ostena-crypto::sealed`, cérémonie de l'ADR-0008) :
- **AES-256-GCM** (conforme, § 2.1.2.1), sous une clé dérivée par PBKDF2-HMAC-SHA256 avec 600 000 itérations et un sel aléatoire de 128 bits ;
- l'en-tête (version, itérations, sel, nonce) est authentifié comme donnée associée.

**Le secret de scellement n'est pas choisi par une personne.** Il est tiré par l'outil : 256 bits.
- Un mot de passe choisi serait un secret de faible entropie, attaquable hors ligne une fois le fichier volé, ce qu'interdit `RègleSecretFaibleEntropie` (§ 2.2.4).
- Avec 256 bits d'entropie, il respecte `RègleTailleCléSym` et `RecoPQTailleCléSym` (§ 2.1.1 : au moins 192 bits quand une sécurité post-quantique est visée, ce qui est le cas pour une racine valide 10 ans, au-delà de 2030 selon `RecoSécuLongTerme`). Il s'aligne sur la clé AES-256. La dérivation n'ajoute qu'une marge.

**Ce secret n'est jamais affiché tel quel.** Il est partagé en trois parts selon le schéma de Shamir sur GF(256), deux quelconques le reconstituant (`vsss-rs`, ADR-0008).
- Une seule part ne donne **aucune information** sur le secret : c'est la sécurité inconditionnelle du schéma de seuil, qui ne repose sur aucun problème calculatoire et n'est donc pas affaiblie par un calcul quantique.
- Chaque part porte une CRC-16, qui ne sert qu'à détecter les fautes de recopie. Une part forgée produit seulement un secret qui n'ouvre pas le scellé (AES-GCM authentifié).

### Risque accepté : authentification classique

Les certificats du tunnel et les grants restent signés en ECDSA P-256, sans composante post-quantique. C'est un écart à la recommandation `RecoSécuLongTerme` et à l'encadré du § 2.2 sur l'authentification post-quantique des produits à longue durée de vie. **Ce n'est pas un écart à une règle.**

- **Portée limitée** : une authentification ne s'attaque pas rétroactivement (« store now, decrypt later »), contrairement à la confidentialité. Celle du tunnel est déjà protégée par l'échange de clés hybride ML-KEM-768. Un grant vit 60 s.
- **Piste de migration** : hybridation par concaténation, explicitement conforme au § 2.2.3 : signer avec ML-DSA (FIPS 204), puis avec ECDSA le couple (message, signature ML-DSA). La signature hybride n'est valide que si les deux le sont.
- **Bloquants actuels** :
  - `aws-lc-rs` n'expose ML-DSA que derrière une fonctionnalité instable ;
  - rustls ne gère pas de certificats hybrides ;
  - les guides ne citent pas encore de profil de certificat hybride.
- **À réexaminer** à chaque version de `aws-lc-rs` et de rustls, et au plus tard avant toute exploitation au-delà de 2030.

### Question de conception ouverte : grants post-quantiques et RDP natif

Un grant hybride ECDSA + ML-DSA-65 porterait une signature d'environ 3,3 Kio. Le champ mot de passe de `TS_INFO_PACKET` ([MS-RDPBCGR] 2.2.1.11.1.1), qui transporte aujourd'hui le grant pour l'accès RDP natif, est limité à **512 octets** terminateur compris : le grant y occupe déjà 450 octets.

La migration post-quantique des grants demandera donc **un autre canal pour l'accès RDP natif**. Quelques pistes, à étudier :
- un grant court servant de référence (jti) à un grant complet retiré par la passerelle auprès du core ;
- l'authentification par la RD Gateway (MS-TSGU) ;
- une pré-authentification hors bande.

Le choix devra préserver l'usage unique et l'absence de secret dans le jeton.

### Coffre-fort (décidé le 2026-11-11)

CLAUDE.md prévoyait pour le coffre-fort « X25519 + ML-KEM-768, Ed25519 + ML-DSA-65 ». X25519 et Ed25519 posant la même question que pour le tunnel et les grants, le coffre-fort s'aligne sur les listes explicites de [PG-083] :

- **Échange de clés et enveloppe des secrets** : P-256 + ML-KEM-768, combinés par une fonction de dérivation de clés (§ 2.2, « Modes d'hybridation conformes » ; § 2.2.2).
- **Signatures** (têtes de chaîne d'audit, mises à jour, futurs grants hybrides) : ECDSA P-256 + ML-DSA-65, hybridées par concaténation : ML-DSA signe le message, puis ECDSA signe le couple (message, signature ML-DSA). La signature n'est valide que si les deux le sont (§ 2.2.3).

Les bloquants d'outillage notés pour l'authentification hybride (ML-DSA derrière une fonctionnalité instable d'`aws-lc-rs`) s'appliqueront au lot du coffre-fort.

### Écarts

#### SSH : la cryptographie de russh dans `ostena-ssh` (décidé le 2026-11-13)

**L'écart.** L'accès SSH natif (ADR-0010) s'appuie sur la bibliothèque russh, qui apporte sa propre cryptographie au lieu de passer par `ostena-crypto`. Pour la liste figée :

| Mécanisme | Implémentation | Conforme au choix d'`ostena-crypto` ? |
|---|---|---|
| Échange de clés ECDH P-256 | `p256` / `elliptic-curve` (RustCrypto) | non : même algorithme, autre implémentation |
| Signatures ECDSA P-256 (clés hôte et utilisateur, certificats) | `ecdsa` / `p256` (RustCrypto), via `ssh-key` | non : même algorithme, autre implémentation |
| Chiffrement AES-256-GCM | `aws-lc-rs` | oui |
| Aléa (clés éphémères, signatures) | `rand` (générateur par thread, réensemencé par le système) | non : `ostena-crypto::rand` lit directement le système |

Les algorithmes restent ceux de la liste figée ; seule l'implémentation diffère.

**Pourquoi.** Interopérer avec OpenSSH côté client et côté cible, avec une bibliothèque maintenue, dans le calendrier du jalon M1. L'alternative, une implémentation SSH propre limitée à la liste figée et entièrement sur `ostena-crypto`, est estimée à 4 à 5 semaines ; elle est notée comme chantier après M1 ([note](../notes/ssh-implementation-propre.md)).

**Confinement.**
- russh n'est dépendance que d'`ostena-ssh`. Les crates cryptographiques qu'il tire (`p256`, `p384`, `p521`, `ecdsa`, `elliptic-curve`, `ed25519-dalek`, `curve25519-dalek`, `aes`, `aes-gcm`, `sha1`, `sha2`, `sha3`, `hmac`, `ml-kem`, `pbkdf2`, `scrypt`, `argon2`, `rand`…) sont interdites partout ailleurs par `deny.toml`, qui n'admet que leurs parents directs dans la chaîne de russh. Une autre crate ne peut ni les déclarer ni les importer ; `cargo deny`, lancé par `cargo xtask ci`, le vérifie.
- **Liste figée, non négociable** : échange `ecdh-sha2-nistp256` seul, chiffrement `aes256-gcm@openssh.com` seul (donc pas de MAC séparé), clés et certificats `ecdsa-sha2-nistp256` seuls. X25519 (`curve25519-sha256`, `mlkem768x25519-sha256`) est désactivé : hors des mécanismes conformes de [PG-083].
- **Strict KEX obligatoire** (CVE-2023-48795). russh ne sait pas l'exiger : il ne l'active que si les deux côtés l'annoncent, sans exposer le résultat. Un **pré-contrôle** propre à `ostena-ssh`, sans dépendance à russh, lit en clair l'identification et le premier `KEXINIT` du pair, refuse sans marqueur strict KEX ou sans algorithme commun avec la liste figée, puis rejoue les octets à russh. La configuration de russh est figée elle aussi, en défense en profondeur.
- **Versions épinglées exactement** : `russh = "=0.65.1"` et `ssh-key = "=0.7.0-rc.11"`, une version préliminaire imposée par russh.
- **Certificats SSH hors de russh** : la signature des certificats OpenSSH par les CA du core et la seconde vérification d'un certificat d'utilisateur par l'agent (autorité, signature stricte low-S, politique) passent par `ostena-crypto` (aws-lc), dans un codec propre à `ostena-ssh` (`ostena_ssh::cert`, ADR-0010) ; russh ne fait que la première vérification, de dates et de signature.

**Impact CSPN.** L'évaluateur doit examiner deux implémentations de P-256 : aws-lc pour le tunnel et les grants, RustCrypto pour SSH. Il doit aussi examiner une dépendance en version préliminaire, et un aléa qui ne passe pas par la façade. Le périmètre de la cible de sécurité doit le dire. Le risque résiduel tient à la qualité d'implémentation de RustCrypto pour ECDH et ECDSA (temps constant, gestion des points), non à l'algorithme.

**Conditions de sortie.** Retour à la règle « toute la cryptographie passe par `ostena-crypto` » :
- par l'implémentation SSH propre (option B, après M1) ;
- ou si russh fait passer ECDH et ECDSA par `aws-lc-rs`, ce qui serait à proposer en amont.

**Construction.** russh est une fonctionnalité par défaut d'`ostena-ssh` (`russh`). Elle est coupée pour la crate de fuzz, car **russh ne compile pas avec le nightly épinglé pour le fuzz** (`nightly-2026-11-01`) :

```text
error[E0391]: cycle detected when computing when `ssh_key::public::key_data::KeyData` needs async drop
  --> ssh-key-0.7.0-rc.11/src/public/key_data.rs:20:1
```

L'erreur vient du compilateur nightly (expérimentation *async drop*), pas du code. **À retester à chaque montée du nightly** : si elle disparaît, la crate de fuzz peut reprendre la fonctionnalité. Le pré-contrôle, seul analyseur de données réseau d'`ostena-ssh` pour l'instant, ne dépend pas de russh et reste fuzzé. `cargo xtask ci` (`check-release`) échoue si le binaire de release lie `ostena-ssh` sans la fonctionnalité `russh`.

**Empreinte sous Windows (diagnostic du 2026-11-14).** Lier le serveur SSH au binaire ajoute 0,84 Mio au working set de l'agent au repos (+12 %), alors que ce code ne s'exécute pas. La répartition page par page (`QueryWorkingSet`) donne : tas privé +16 Kio, pages d'image privées +92 Kio, pages d'image partagées +752 Kio. Trois DLL nouvelles sont chargées au démarrage :

| DLL | Pages | Rôle |
|---|---|---|
| `combase.dll` | 340 Kio | runtime COM |
| `msvcp_win.dll` | 188 Kio | bibliothèque C++ système |
| `oleaut32.dll` | 132 Kio | automation OLE |

Elles viennent de l'import statique d'`oleaut32` pour deux fonctions (`SysStringLen`, `SysFreeString` : chaînes BSTR de la crate `windows-strings`, tirée par `pageant`, l'agent SSH de PuTTY que russh lie sous Windows). Ni `user32`, ni `gdi32`, ni `win32u` ne sont chargées. Le runtime COM entre toutefois dans un service à SID restreint qui n'en a pas l'usage : c'est de la surface d'attaque autant que de la mémoire.

**Décision** :
- **Chargement différé** d'`oleaut32` (`/DELAYLOAD:oleaut32.dll`, `delayimp.lib`) à la liaison du serveur SSH dans l'agent (PR 6) : ces fonctions ne servent qu'à parler à Pageant, ce que l'agent ne fait jamais. Mesuré : les trois DLL ne sont plus chargées, et l'écart tombe à +0,05 Mio (6,87 → 6,92 Mio).
- **Contrôle dans `cargo xtask ci`** à la PR 6 : aucune DLL d'interface graphique ou COM (`user32`, `gdi32`, `win32u`, `combase`, `ole32`, `oleaut32`) ni dans les imports statiques du binaire, ni dans les DLL chargées par l'agent au repos.
- **Correctif amont à proposer après M1** : rendre `pageant` optionnel dans russh ([note](../notes/russh-correctifs-amont.md)).
- **Remesure obligatoire en PR 6**, avec le serveur SSH réel dans l'agent.

**Engagements bloquants pour la PR 6** (décision du responsable du projet, 2026-11-14) :
1. `/DELAYLOAD` d'`oleaut32` en place, et remesure : **aucune DLL chargée en plus au repos** par rapport à l'agent sans SSH (ni `oleaut32`, ni `combase`, ni `msvcp_win`) ;
2. le contrôle de `cargo xtask ci` ci-dessus est actif et passe (imports statiques **et** DLL chargées au repos) ;
3. si l'un des deux échoue, **la PR 6 ne fusionne pas** sans décision explicite du responsable du projet.
- **Seuil d'empreinte double** : une régression d'empreinte n'est bloquante que si elle dépasse **+10 % et plus de 1 Mio** en valeur absolue, pour ne pas déclencher sur une base de quelques Mio (ADR-0007).

**Mise en œuvre à la PR 6 (2026-11-25)** :
- **Chargement différé** : `crates/ostena-cli/build.rs` passe `/DELAYLOAD:oleaut32.dll` et `delayimp.lib` à l'éditeur de liens pour le binaire `ostena`, sous Windows avec MSVC et seulement avec la fonctionnalité `ssh`.
- **Imports statiques** : `cargo xtask check-release` lit le répertoire d'imports et celui des imports différés du binaire PE (analyseur borné, sans dépendance, `xtask/src/pe.rs`) et échoue si l'une des six DLL interdites est importée statiquement, ou un API set qui se résout vers l'une d'elles (par préfixe : `api-ms-win-core-com-`, `api-ms-win-core-marshal-`, `api-ms-win-core-winrt-`, `ext-ms-win-com-`, `ext-ms-win-ole32-`, `ext-ms-win-ntuser-`, `ext-ms-win-rtcore-ntuser-`, `api-ms-win-rtcore-ntuser-`, `ext-ms-win-gdi-`, `ext-ms-win-rtcore-gdi-`, `api-ms-win-gdi-`). Aucun API set propre à `oleaut32` n'est identifié. Une DLL interdite en import différé est admise : elle n'est chargée qu'à l'appel. Le même contrôle refuse un binaire de release construit sans la fonctionnalité `ssh`.
- **Modules chargés au repos** : `cargo xtask footprint` relève, pour chaque état, les bibliothèques chargées par l'agent sans SSH et avec SSH (`/proc/<pid>/maps` sous Linux, modules du processus sous Windows). Il échoue si l'agent avec SSH charge un module que la référence ne charge dans aucun état, ou l'une des six DLL interdites. Une liste qui ne peut pas être celle de l'agent le fait échouer aussi : lecture impossible, sous Windows une liste sans `ntdll.dll` et `kernel32.dll`, sous Linux une table sans l'exécutable (le binaire musl statique ne charge aucune bibliothèque partagée : une liste vide y est normale). La comparaison porte sur tous les états de la référence parce que, sans lien au core, l'écoute SSH est le seul socket de l'agent : Winsock charge alors son fournisseur `mswsock.dll`, que la référence charge dès qu'elle se connecte (relevé par la CI Windows le 2026-11-25).
- **Seuil d'empreinte** : le même outil échoue si l'agent avec SSH dépasse la référence de plus que le plafond accepté (décision du 2026-11-25 ci-dessous).

**Remesure sous Linux** (conteneur de développement, mémoire résidente au repos, `cargo xtask footprint` ; la référence est l'agent construit sans la fonctionnalité `ssh`, l'autre mesure l'agent avec `[agent.ssh]` à l'écoute). Binaire statique musl, l'artefact Linux de release, que la CI mesure désormais (`--target x86_64-unknown-linux-musl`) :

| État | Sans SSH | Avec SSH | Écart | Lié seulement |
|---|---|---|---|---|
| sans liaison | 4,67 Mio | 6,58 Mio | +1,91 Mio (+40,9 %) | +0,70 Mio |
| non connecté | 7,09 Mio | 8,93 Mio | +1,83 Mio (+25,8 %) | +1,44 Mio |
| connecté | 7,80 Mio | 9,44 Mio | +1,63 Mio (+20,9 %) | +1,13 Mio |

« Lié seulement » : le binaire avec SSH, lancé sans `[agent.ssh]` (mesure de diagnostic). Deux exécutions donnent les mêmes valeurs à 0,02 Mio près. Le binaire glibc donne des écarts du même ordre (+1,58 à +1,85 Mio, sur 7,27 à 10,73 Mio), plus bruités (±0,3 Mio).

**Analyse** :
- **PSS et mémoire privée égalent la mémoire résidente** pour le binaire statique : un seul processus projette ses pages, rien n'est partagé. Changer de métrique ne change pas le verdict.
- **L'écart est fait de pages de code** : `.text` résident +1,4 Mio, `.rodata` et `.eh_frame` +0,16 à +0,29 Mio, en-têtes et `.rela.dyn` +44 Kio, segment inscriptible (relro, GOT, `.data`) +64 Kio dont +48 Kio modifiés, tas et piles +0 à +170 Kio. Le binaire passe de 9,7 à 12,2 Mo (`.text` +1,9 Mo, `.data` +194 Kio, `.data.rel.ro` +32 Kio) et de 11 911 à 13 728 relocations `R_X86_64_RELATIVE`.
- **L'essentiel tient à la liaison**, pas au serveur : sans `[agent.ssh]`, le binaire avec SSH coûte déjà +0,7 à +1,44 Mio. Le code du chemin commun est le même (les fonctionnalités unifiées n'ajoutent rien de lourd), mais avec la LTO complète et une seule unité de compilation, il s'éparpille sur davantage de pages, que le noyau projette par blocs. Le serveur en marche ajoute +0,4 à +0,5 Mio une fois les clés créées ; la mesure « sans liaison » comprend leur création au premier démarrage (+1,2 Mio).

**Pistes essayées** (sans changer le comportement) :
- **Non-PIE** (`relocation-model=static`) : refusé. Il retire l'ASLR du binaire en production, pour un gain borné au segment relogé (+48 Kio modifiés d'écart).
- **Profil de release** : déjà `lto = "fat"`, `codegen-units = 1`, `strip = true`. `panic = "abort"` réduirait `.eh_frame` et `.gcc_except_table`, mais change le comportement (une panique d'une tâche arrête l'agent) : non essayé.
- **`opt-level = "s"`** (mesure seulement) : 3,61 / 5,09 / 5,32 Mio sans SSH, 5,43 / 6,27 / 6,65 Mio avec, soit un agent avec SSH plus petit que l'agent actuel sans SSH. Mais l'écart reste au-dessus du seuil (+1,18 à +1,83 Mio, +23 à +51 %), et l'effet sur la latence n'est pas mesuré.
- **Initialisation paresseuse** : elle ne pourrait retirer que la part du serveur en marche (≤ 0,5 Mio clés créées) ; la part de la liaison seule dépasse déjà 1 Mio dans deux états.

**Mesures sous Windows** (CI GitHub, windows-2022, working set au repos) : 6,02 → 6,94 Mio sans liaison (+0,93 Mio, +15,4 %), 8,18 → 8,56 Mio non connecté (+0,38 Mio), 8,86 → 9,25 Mio connecté (+0,39 Mio). Le seuil double n'y est pas dépassé. Imports statiques : `kernel32`, `api-ms-win-core-synch-l1-2-0`, `bcryptprimitives`, `ntdll`, `advapi32`, `ws2_32`, `psapi`, `iphlpapi` ; `oleaut32.dll` en import différé seulement ; aucune DLL d'interface graphique ou COM chargée au repos. Les engagements 1 et 2 sont tenus.

**Sous Linux, le seuil double est dépassé dans les trois états** (+10 % et +1 Mio à la fois), sans réduction suffisante possible sans changer le comportement ou le profil.

**Décision du 2026-11-25 (responsable du projet)** : l'écart d'empreinte dû à la liaison du serveur SSH est **accepté**, pour les motifs suivants : il est fait de pages de code, sans bibliothèque ni DLL chargée en plus ; la mémoire anonyme ne prend que 0 à +170 Kio ; l'agent avec SSH reste à 9,44 Mio connecté sous Linux et 9,25 Mio sous Windows, loin de l'objectif indicatif de 20 Mio. L'engagement 3 est levé par cette décision explicite. En conséquence :
- `cargo xtask footprint` borne désormais le coût du serveur SSH par un **plafond daté**, au lieu du seuil double : **2,25 Mio sous Linux** (mesure maximale +1,91 Mio, plus environ 0,3 Mio de bruit) et **1,25 Mio sous Windows** (mesure maximale +0,93 Mio, plus le bruit). Au-delà, la CI échoue. Le contrôle des modules et des DLL interdites est inchangé.
- Le seuil double (+10 % et +1 Mio) reste la règle pour toute autre régression d'empreinte (CLAUDE.md, ADR-0007) ; il n'est pas automatisé par rapport à `dev`.
- Une PR séparée mesure la compilation de l'agent en taille (`opt-level = "s"`), qui ramènerait l'agent avec SSH sous l'agent actuel sans SSH ; elle n'est retenue que si le banc de latence SSH ne régresse pas de plus de 10 % au p99 et reste sous l'objectif de 3 ms.

**Révision du 2026-11-25 (responsable du projet), plafond Linux relevé à 2,75 Mio.** Avec l'autorisation SSH du core (PR 5b, ADR-0014), la CI mesure +2,31 Mio sans liaison, +2,04 Mio non connecté et +2,17 Mio connecté, contre +1,95, +1,62 et +1,49 Mio auparavant. Le code de l'agent n'a pas changé. La mémoire anonyme ne prend que +20 Kio. La hausse est faite de pages adossées au binaire : le binaire étant unique, le core y grossit (environ 4 000 lignes, dont l'autorité SSH qui appelle `ostena-ssh`), ce qui change la disposition du code et les pages lues autour de chaque défaut de page. Ces pages sont partagées et récupérables par le noyau. Le plafond devient 2,75 Mio sous Linux (mesure maximale +2,31 Mio, plus environ 0,4 Mio de bruit) ; il reste 1,25 Mio sous Windows. La PR qui mesure la compilation en taille reste ouverte pour réduire ce coût.

**Profil optimisé pour la taille (mesuré le 2026-11-25, PR 6bis).** Le binaire `ostena` est unique : un `opt-level` global touche aussi le core. Trois variantes ont été comparées au profil actuel (`opt-level = 3`, LTO complète, une unité de compilation). Critères de refus fixés d'avance : p99 de latence qui régresse de plus de 10 % ou dépasse 3 ms, ou débit du relais qui régresse de plus de 10 %.

Méthode : conteneur de développement partagé (4 CPU, bruit d'autres compilations). `cargo bench -p ostena-ssh --bench relay` donne l'aller-retour de 64 octets et l'établissement de session à travers l'agent. Le débit est mesuré par une sonde locale ajoutée au même banc, non versionnée (32 Mio renvoyés par la cible en écho, 128 Kio en vol, 3 mesures par exécution). Les variantes sont exécutées en alternance, 6 fois chacune ; on donne la médiane et l'étendue. Empreinte : `cargo xtask footprint --target x86_64-unknown-linux-musl`.

| Mesure (via l'agent, `dev` 7b7d7d2) | `opt-level = 3` (actuel) | `"s"` + chemin chaud à 3 (retenu) | Écart |
|---|---|---|---|
| Aller-retour 64 octets, p50 | 70 µs [31–100] | 32 µs [27–98] | dans le bruit |
| Aller-retour 64 octets, p99 | 168 µs [125–215] | 128 µs [78–215] | −24 % (bruit) |
| Établissement de session, p50 | 3,84 ms [3,48–4,45] | 3,97 ms [3,57–4,07] | +3,6 % |
| Établissement de session, p99 | 5,19 ms [4,14–8,75] | 5,03 ms [4,16–7,11] | −3 % |
| Débit du relais (18 mesures) | 260 Mio/s [148–316] | 249 Mio/s [216–297] | −4 % |
| Latence ajoutée du tunnel, p99 (3 exécutions) | 0,12 ms [0–0,29] | 0,15 ms [0,12–0,20] | dans le bruit |
| Agent avec SSH, sans liaison | 6,78 Mio | 6,26 Mio | −0,52 Mio |
| Agent avec SSH, non connecté | 9,29 Mio | 8,55 Mio | −0,74 Mio |
| Agent avec SSH, connecté | 10,07 Mio | 8,70 à 8,76 Mio | −1,31 à −1,37 Mio |
| Coût du SSH (avec − sans) | +2,02 / +1,61 / +1,86 Mio | +1,88 / +1,68 / +1,24 à +1,30 Mio | inchangé, sous le plafond |
| Binaire musl | 13 246 608 octets | 11 223 184 octets | −15 % |

Variantes refusées :
- **`opt-level = "s"` global** (mesuré sur `dev` a1b0e62, 3 exécutions) : l'agent avec SSH tombe à 5,50 / 6,40 / 6,67 Mio et le binaire à 8,0 Mo, mais le débit du relais perd 18 % (224 contre 273 Mio/s), l'établissement de session prend +49 % au p50 (2,75 contre 1,85 ms ajoutées) et l'aller-retour p99 +28 % (204 contre 160 µs). Le chiffrement, les échanges de clés et les signatures compilés en taille coûtent trop. Refusé.
- **`"s"` + chemin chaud étendu** (22 crates de plus à 3 : `ssh-key`, `der`, `ostena-scope`, `tracing`, etc.) : l'établissement de session revient au niveau actuel, mais l'aller-retour p99 médian dépasse le critère (190 µs, +13 %) et le gain d'empreinte diminue (9,07 Mio connecté). Refusé.
- **`opt-level = "z"`** : non essayé. Le « s » global échoue déjà sur le débit ; « z » ne réduirait que le code froid, déjà en « s » dans la variante retenue.

**Décision** : le profil de release compile en taille (`opt-level = "s"`), sauf les crates du chemin de données et de l'établissement de session, gardées à `opt-level = 3` par des surcharges par paquet dans `Cargo.toml` : runtime (`tokio`, `mio`, `bytes`, `futures-util`), relais SSH (`russh`, `russh-cryptovec`, `ssh-cipher`, `ssh-encoding`, `ostena-ssh`, `ostena-tunnel`, `ostena-crypto`), chiffrement symétrique, MAC et hachage, échange de clés et signatures (courbes NIST, X25519, Ed25519, ML-KEM, SHA-3), TLS et QUIC du tunnel (`aws-lc-rs`, `aws-lc-sys` dont le code C, `rustls`, `quinn*`). Le profil `bench` en hérite : les bancs mesurent le binaire livré. Aucun critère n'est franchi ; l'agent avec SSH gagne 0,5 à 1,4 Mio de mémoire résidente au repos et le binaire 2 Mo. Le coût propre du SSH (avec − sans) ne baisse pas : les deux binaires rétrécissent ensemble. Les plafonds d'`xtask` restent inchangés. Une crate ajoutée au chemin chaud (pilote RDP, nouveau chiffrement) rejoint cette liste, avec une mesure des bancs.

**Réexamen** de l'écart et des épinglages au premier des trois événements : sortie de `ssh-key` 0.7 stable, avis RustSec sur russh ou ses dépendances, **fin du jalon M1 au plus tard** (fin février 2027).

#### PostgreSQL : la cryptographie de `sqlx-postgres` dans `ostena-core` (décidé le 2026-11-14)

**Constat.** Le pilote PostgreSQL de sqlx implémente lui-même l'authentification SCRAM-SHA-256 et MD5, avec `sha2`, `hmac`, `hkdf`, `md-5` et `rand` (RustCrypto). Ces dépendances sont inconditionnelles, et aucun pilote en Rust pur n'y échappe (`tokio-postgres` fait pareil).

**Décision : exception acceptée, confinée et neutralisée.**
- **Confinement** : `deny.toml` n'admet ces crates que sous `sqlx-postgres` (et `sqlx-core` pour le `sha2` des sommes de contrôle des migrations). sqlx n'est admis que sous `ostena-core`.
- **Neutralisation** : en production, le core ne joint PostgreSQL que par le socket Unix avec l'authentification `peer`. Aucun mot de passe n'est configurable : si le serveur demande SCRAM ou MD5, la connexion échoue. Le core vérifie aussi `system_user` au démarrage et refuse toute autre méthode (`CORE-E003`, ADR-0011). Ce code n'est donc jamais exécuté en production.
- **Pas de TLS vers la base** : celle de sqlx ajoute les racines publiques à la CA configurée (ADR-0011).

**Réexamen** : avec la base distante en TLS épinglée (après M1), qui ramènera SCRAM en production.

#### Question ouverte : échange de clés SSH hybride post-quantique

russh 0.65.1 ne propose qu'un hybride X25519 + ML-KEM-768 (`mlkem768x25519-sha256`), hors liste. Une variante P-256 + ML-KEM-768 est décrite par un brouillon de l'IETF (`mlkem768nistp256-sha256`). Sa prise en charge par russh et par OpenSSH reste à vérifier. En attendant, l'échange SSH reste classique (ECDH P-256), comme l'authentification du tunnel (voir le risque accepté plus haut).

## Conséquences

- **`ostena-crypto`** n'expose plus Ed25519. Les algorithmes ne sont ni négociables ni configurables : `grant.signature_algorithm` n'accepte que `ecdsa-p256-sha256` en production (`CFG-P004`).
- **Interopérabilité** : les deux extrémités du tunnel sont à nous. N'accepter qu'un groupe et qu'une suite ne coûte rien en interopérabilité, et supprime toute rétrogradation.
- **Veille des guides** : toute nouvelle version de [PG-083] ou de [PA-079] impose de revoir ce tableau. Les identifiants de règles cités permettent de vérifier rapidement ce qui a changé.
