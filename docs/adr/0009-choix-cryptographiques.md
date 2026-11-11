# ADR-0009 : Choix cryptographiques et conformité aux guides ANSSI

- **Statut** : Accepté
- **Date** : 2026-11-11
- **Révision** : 2026-11-11, algorithmes du coffre-fort décidés (P-256 + ML-KEM-768, ECDSA P-256 + ML-DSA-65)

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

**La phrase secrète n'est pas choisie par une personne.** Elle est tirée par l'outil : 30 caractères base32, soit 150 bits.
- Une phrase choisie serait un secret de faible entropie, attaquable hors ligne une fois le fichier volé, ce qu'interdit `RègleSecretFaibleEntropie` (§ 2.2.4).
- Avec 150 bits, la clé respecte `RègleTailleCléSym` (§ 2.1.1) et `RecoPQTailleCléSym` (au moins 192 bits de clé AES et 150 bits d'entropie, hors de portée d'une recherche exhaustive, même quantique au sens du § 2.1.1). La dérivation n'ajoute qu'une marge.
- La phrase est affichée une seule fois, en deux moitiés, pour deux dépositaires.

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

## Conséquences

- **`ostena-crypto`** n'expose plus Ed25519. Les algorithmes ne sont ni négociables ni configurables : `grant.signature_algorithm` n'accepte que `ecdsa-p256-sha256` en production (`CFG-P004`).
- **Interopérabilité** : les deux extrémités du tunnel sont à nous. N'accepter qu'un groupe et qu'une suite ne coûte rien en interopérabilité, et supprime toute rétrogradation.
- **Veille des guides** : toute nouvelle version de [PG-083] ou de [PA-079] impose de revoir ce tableau. Les identifiants de règles cités permettent de vérifier rapidement ce qui a changé.
