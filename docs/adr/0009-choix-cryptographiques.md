# ADR-0009 : Choix cryptographiques et conformité aux guides ANSSI

- **Statut** : Accepté
- **Date** : 2026-11-11
- **Révision** : 2026-11-11, algorithmes du coffre-fort décidés (P-256 + ML-KEM-768, ECDSA P-256 + ML-DSA-65)
- **Révision** : 2026-11-13, écart SSH : cryptographie de russh dans `ostena-ssh`

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

**Réexamen** de l'écart et des épinglages au premier des trois événements : sortie de `ssh-key` 0.7 stable, avis RustSec sur russh ou ses dépendances, **fin du jalon M1 au plus tard** (fin février 2027).

#### Question ouverte : échange de clés SSH hybride post-quantique

russh 0.65.1 ne propose qu'un hybride X25519 + ML-KEM-768 (`mlkem768x25519-sha256`), hors liste. Une variante P-256 + ML-KEM-768 est décrite par un brouillon de l'IETF (`mlkem768nistp256-sha256`). Sa prise en charge par russh et par OpenSSH reste à vérifier. En attendant, l'échange SSH reste classique (ECDH P-256), comme l'authentification du tunnel (voir le risque accepté plus haut).

## Conséquences

- **`ostena-crypto`** n'expose plus Ed25519. Les algorithmes ne sont ni négociables ni configurables : `grant.signature_algorithm` n'accepte que `ecdsa-p256-sha256` en production (`CFG-P004`).
- **Interopérabilité** : les deux extrémités du tunnel sont à nous. N'accepter qu'un groupe et qu'une suite ne coûte rien en interopérabilité, et supprime toute rétrogradation.
- **Veille des guides** : toute nouvelle version de [PG-083] ou de [PA-079] impose de revoir ce tableau. Les identifiants de règles cités permettent de vérifier rapidement ce qui a changé.
