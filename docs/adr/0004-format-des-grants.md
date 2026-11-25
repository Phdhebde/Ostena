# ADR-0004 : Format des grants

- **Statut** : Accepté
- **Date** : 2026-11-11
- **Révision** : 2026-11-11, signature ECDSA P-256 / SHA-256 (algorithme 2) au lieu d'Ed25519, absent des guides ANSSI (ADR-0009)
- **Révision** : 2026-11-25, format v2 (184 octets) : liaison signée à la session de connexion et au compte cible (jalon M1, PR 5a) ; la v1 est refusée

## Contexte

Le core autorise une session et remet à l'utilisateur un *grant* : un jeton court que la passerelle (agent) vérifie avant d'ouvrir la session vers la cible. Le grant porte l'autorisation, jamais un secret. Contraintes :

- il doit souvent transiter par un client natif, dans un champ prévu pour un identifiant ou un mot de passe : il doit être **compact** ;
- l'algorithme est figé (ECDSA P-256 / SHA-256, ADR-0009) et **ne doit pas être négociable** par le jeton ;
- le décodeur reçoit des données hostiles : il doit être **simple, strict et fuzzable** ;
- un grant ne sert **qu'une fois**, même après un redémarrage de l'agent.

## Décision

### Encodage : binaire fixe maison

Alternatives étudiées :

| Option | Taille | Raison du rejet |
|---|---|---|
| CWT / COSE_Sign1 (CBOR) | ~180–220 o | parseur CBOR (dépendance, surface d'attaque), en-tête `alg` négociable, plusieurs encodages possibles d'un même grant |
| JWT / JWS | 400+ caractères | JSON et double base64, historique `alg: none` et confusion d'algorithme, trop long pour un champ mot de passe RDP |
| PASETO v4.public | ~300 caractères | JSON, dépendance, taille |
| Protobuf / postcard / bincode | ~120–160 o | dépendance, encodage non canonique (protobuf) ou format lié à une bibliothèque |

Retenu : une **structure binaire de taille fixe**. Le décodeur lit à des positions constantes, sans allocation ni dépendance. Un grant n'a qu'un seul encodage possible, et aucun champ n'est négociable.

### Format v2 (184 octets, entiers big-endian)

| Offset | Taille | Champ | Règle |
|---|---|---|---|
| 0 | 3 | magic `OSG` | sinon `GRT-E001` |
| 3 | 1 | version = 2 | sinon `GRT-E002` ; la v1 (168 octets, sans liaison) est refusée par sa longueur (`GRT-E001`) |
| 4 | 1 | algorithme = 2 (ECDSA P-256 / SHA-256) | sinon `GRT-E003`, même si la signature est valide ; la valeur 1 (Ed25519, premier projet) est refusée |
| 5 | 1 | protocole : 1 SSH, 2 RDP, 3 VNC, 4 Web | sinon `GRT-E004` |
| 6 | 2 | réservé | doit valoir 0 (`GRT-E001`) |
| 8 | 8 | kid : 8 premiers octets du SHA-256 de la clé publique au format SEC1 non compressé (65 octets, `0x04 ‖ x ‖ y`) | |
| 16 | 16 | jti : identifiant aléatoire de 128 bits | |
| 32 | 16 | sujet : UUID de l'utilisateur dans le core | |
| 48 | 16 | ressource : UUID de la cible dans l'inventaire | |
| 64 | 16 | audience : UUID du groupe de passerelles autorisé | sinon `GRT-E011` |
| 80 | 4 | droits (champ de bits) | bit inconnu : `GRT-E004` |
| 84 | 4 | durée de session maximale (s) | 0 : `GRT-E004` ; au-dessus de la politique : `GRT-E009` |
| 88 | 8 | iat : émission et début de validité (s Unix) | |
| 96 | 8 | exp : expiration, exclue (s Unix) | `exp ≤ iat` : `GRT-E004` ; `exp − iat` au-dessus de la politique : `GRT-E009` |
| 104 | 16 | liaison : session de connexion et compte cible (voir plus bas) | comparée par le vérificateur qui connaît les deux |
| 120 | 64 | signature ECDSA P-256 / SHA-256 brute `r ‖ s` (32 + 32 octets, big-endian), forme low-S | |

Droits (inchangés depuis la v1) : presse-papiers vers la cible (bit 0), presse-papiers depuis la cible (1), dépôt de fichiers (2), récupération de fichiers (3), redirection de lecteurs (4), d'imprimante (5), de l'audio (6), redirection de ports SSH (7), agent forwarding SSH (8). Toute évolution du format passe par une nouvelle version.

### Liaison (v2)

Le compte cible (jusqu'à 256 octets) ne tient pas dans un format de taille fixe, et le champ mot de passe RDP ne laisse que 23 octets de marge au format v1. Le grant porte donc une **liaison** de 16 octets :

```text
liaison = SHA-256("ostena-grant-binding-v1\0" ‖ session de connexion (16 octets) ‖ longueur du compte (u16, big-endian) ‖ compte)[0..16]
```

calculée par `ostena-crypto` (`ostena_grant::Binding::of`). Le préfixe de longueur empêche le compte de glisser dans la session. L'émetteur la calcule à partir de la session de connexion et du compte qu'il autorise ; le vérificateur la recalcule à partir de ce qu'il connaît par ailleurs et compare. **Le grant ne permet pas de retrouver la session ni le compte** : il ne sert qu'à vérifier.

Pour SSH (ADR-0010), l'agent connaît la session de connexion (identifiant de clé du certificat utilisateur) et le compte (nom d'utilisateur SSH) : il exige la liaison après avoir consommé le jti (`TUN-E010`), si bien qu'un grant qui ne correspond pas est brûlé.

**Ce que la liaison garantit** : un grant signé pour la session S et le compte A ne sert pas pour une autre session ni un autre compte, même si l'agent reçoit des paramètres de session erronés. Cela s'ajoute au contrôle du compte dans `session_params`, reçu par le tunnel mTLS.

**Ce qu'elle ne garantit pas** :
- elle ne dit pas *quel* compte ni *quelle* session : un lecteur du grant ne les apprend pas (c'est voulu, mais l'audit doit les tirer du registre des grants du core, pas du jeton) ;
- elle ne protège pas contre un core ou un agent compromis, qui détient les données liées ;
- **troncature à 128 bits** : trouver deux couples (session, compte) de même liaison demande environ 2^64 essais (paradoxe des anniversaires), mais seulement si l'attaquant choisit librement **les deux** couples. Ici, l'un des deux est imposé : c'est un compte sur lequel l'utilisateur a un droit, pour sa propre session, que le core a signé. Usurper un autre compte avec ce grant revient à trouver une seconde préimage, soit environ 2^128 essais, hors de portée. Un utilisateur qui ferait signer un compte de son choix n'obtient de grant que pour un compte autorisé : la collision ne lui ouvre rien de plus que ce qu'il a déjà. 128 bits est aussi la taille du jti et des identifiants du format.

Pour un protocole sans session de connexion (à venir), la liaison est calculée avec l'identifiant de la session qui en tient lieu ; le choix sera consigné avec ce protocole.

**Le grant ne contient que l'identifiant de la ressource.** L'agent n'a pas de base de données : il reçoit l'hôte, le port et le compte cible du core, par le tunnel authentifié en mTLS, quand il demande les paramètres de session. Il applique quand même `ostena-scope` (CIDR, épinglage de l'IP résolue, blocage des adresses de métadonnées et locales) à l'hôte et au port reçus.

### Signature

- **La signature couvre tous les octets qui la précèdent**, c'est-à-dire `octets[0..120]` : magic, version, algorithme, kid et liaison compris. Ces octets sont précédés d'un préfixe de séparation de domaine, `"ostena-grant-v2\0"` (16 octets, `"ostena-grant-v1\0"` en v1), signé mais non transmis. Une signature produite par la même clé pour un autre usage ne peut donc pas passer pour un grant.
- **Signature ECDSA P-256 / SHA-256 (FIPS 186-5), au format brut de 64 octets** `r ‖ s`, pas en DER : le grant garde sa taille fixe de 184 octets (246 caractères), ce que vérifient des assertions à la compilation.
- **La vérification est stricte.** ECDSA est malléable : si `(r, s)` est valide, `(r, n − s)` l'est aussi. Le signataire produit donc toujours la forme **low-S** (`s ≤ (n − 1)/2`), et `ostena-crypto` refuse, avant la vérification d'`aws-lc-rs` :
  - `r` ou `s` nul, ou supérieur ou égal à l'ordre du groupe n ;
  - `s` au-dessus de `(n − 1)/2` (high-S), même si la signature est mathématiquement valide ;
  - une clé publique qui n'est pas un point SEC1 non compressé situé sur la courbe.

  Un message n'a ainsi qu'une signature acceptée par clé. L'anti-rejeu repose de toute façon sur le jti et pas sur les octets de la signature. Chaque refus a son test, dont un vecteur RFC 6979 high-S accepté par la vérification ECDSA de base et refusé par la nôtre.
- **Pourquoi pas Ed25519** (premier projet de cet ADR) : EdDSA n'est cité ni par le guide ANSSI-PG-083 v3.00 ni par le guide de sélection ANSSI-PA-079 (voir ADR-0009). P-256 permettra aussi de garder la clé de signature du core dans un HSM. Rien n'était déployé : la valeur 1 est simplement refusée, sans période de transition.

### Forme texte

**base64url sans remplissage** (RFC 4648 §5), soit **246 caractères**, avec un décodage strict (alphabet, longueur et bits de fin canoniques : 184 octets laissent 4 bits inutilisés dans le dernier caractère, qui doivent être nuls).

Vérifié dans [MS-RDPBCGR] 2.2.1.11.1.1 (TS_INFO_PACKET) : le champ *Password* accepte au plus **512 octets terminateur nul compris**, en UTF-16 si `INFO_UNICODE` est positionné. 246 caractères occupent 494 octets (492 plus 2 pour le terminateur), soit **18 octets de marge** (62 en v1). Le format ne peut plus grandir que de 7 octets (191 octets, 255 caractères, 512 octets) sans sortir de ce champ. Une assertion à la compilation (`format.rs`) garantit cette limite. Les limites propres aux interfaces des clients (boîtes de saisie) restent à confirmer en laboratoire.

### Ordre de vérification et codes

1. Longueur exacte de 184 octets, magic, version, algorithme (`E001`, `E002`, `E003`).
2. Recherche du kid : inconnu (`E005`), clé révoquée (`E012`), clé retirée (`E013`).
3. **Signature** (`E006`). Aucun autre champ n'est utilisé avant.
4. Champs : réservé, protocole, droits, durées (`E001`, `E004`).
5. Audience (`E011`), durée de vie et de session maximales (`E009`).
6. Fenêtre de validité : pas encore valide si `iat > now + tolérance` (`E007`), expiré si `now ≥ exp` (`E008`).
7. Consommation du jti : déjà utilisé, ou émis avant la dernière réparation (`E010`). Si l'anti-rejeu est indisponible, le grant est refusé (`E014`).

Politique par défaut côté vérificateur : tolérance d'horloge de 5 s, durée de vie maximale de 300 s, session maximale de 12 h. Durée de vie émise par défaut : **60 s**. Les codes `GRT-E001` à `GRT-E014` sont stables. Les événements émis sont `grant.accepted` (jti, kid, sujet, ressource, protocole, droits) et `grant.rejected` (code et message).

### Jeu de clés, rotation, révocation

- Le core signe avec une clé active (PKCS#8 dans un `Secret`). Les agents ne détiennent que des clés publiques, indexées par kid.
- **Rotation** :
  1. diffuser la nouvelle clé publique à toutes les passerelles ;
  2. la rendre active sur le core une fois la diffusion terminée ;
  3. fixer une date de retrait à l'ancienne clé, au plus tôt « durée de vie maximale + tolérance » après le basculement.
- **Révocation immédiate** : une clé révoquée est refusée tout de suite, même avant sa date de retrait, avec un code distinct de « kid inconnu » (`E012` contre `E005`). Elle reste dans le jeu de clés pour que le refus soit explicite, et la réinsérer ne lève pas la révocation.

### Anti-rejeu

- **Le trait** : `ReplayStore::consume(jti, exp)`, asynchrone. Il est atomique et sa réponse doit être durable avant d'être rendue. `Chain(A, B)` enchaîne deux magasins : B n'est consulté que si A répond « nouveau », et un grant n'est accepté que si tous le voient pour la première fois.
- **Agent** : `FileReplayStore`.
  - Journal en ajout seul : en-tête `OSTRPL01` et barrière, puis des enregistrements de 28 octets (jti, exp, CRC-32).
  - `fsync` avant d'accepter le grant, soit 1 à 10 ms, dans le budget d'établissement de session.
  - Verrou exclusif (fichier `.lock`).
  - Compactage par fichier temporaire, `fsync` et renommage.
  - Conservation des entrées une heure après leur expiration, en cas de recul de l'horloge.
- **Core (à venir)** : quand l'agent demande au core les paramètres de session, le core vérifie le grant (`Verifier::check`) et **consomme aussi le jti dans PostgreSQL**. Cela couvre plusieurs agents d'un même groupe, qui ne partagent pas de fichier. Côté agent, l'enchaînement sera `Chain(FileReplayStore, consommation distante par le core)`.
- **Journal endommagé** :
  - un dernier enregistrement tronqué (écriture jamais validée) est supprimé à l'ouverture ;
  - tout autre dommage (en-tête, somme de contrôle) **empêche l'agent de démarrer**. La reprise est explicite : `ostena agent replay-store repair --path <journal>` (voir `docs/exploitation/agent-anti-rejeu.md`) ;
  - la reprise copie l'original en `<journal>.corrupt-<horodatage>` sans le modifier, garde les enregistrements sains, journalise l'événement `replay_store.repaired` et pose une **barrière** égale à « maintenant + durée de vie maximale + tolérance ». Tout grant qui expire avant cette barrière est refusé (`E010`), parce qu'il a pu être consommé dans un enregistrement perdu. Les utilisateurs concernés demandent simplement un nouveau grant.

### Horloge

- **L'agent exige une horloge synchronisée.** Sous Debian : chrony avec NTS (RFC 8915) vers des sources internes. Sous Windows Server, W32Time ne gère que NTP : il faut des sources internes de confiance, et NTS via un composant tiers si la politique l'exige.
- **Si la dérive dépasse la tolérance de 5 s** :
  - agent **en retard** de d > 5 s : les grants frais sont refusés comme « pas encore valides » (`E007`) jusqu'à iat + d − 5, puis acceptés jusqu'à exp + d. La fenêtre est décalée mais pas élargie au-delà de d, et le jti reste à usage unique ;
  - agent **en avance** de d : la durée de vie utile tombe à 60 − d s, et pour d ≥ 60 s tous les grants sont refusés comme expirés (`E008`).
- Les messages de `E007` et `E008` invitent à vérifier la synchronisation. **À venir** : l'établissement du tunnel mesurera l'écart avec le core ; au-delà de la tolérance, l'agent lèvera une alarme et refusera les sessions plutôt que de produire des refus incompréhensibles.

### Fuzzing

Une cible `cargo-fuzz` (`grant_decode`) exerce tous les décodeurs : binaire, texte et vérification complète avec une clé de test publique (RFC 6979, annexe A.2.5). Elle vit dans `fuzz/`, hors du workspace, avec un nightly daté. La CI la fait tourner 30 s sous AddressSanitizer, sous Linux, et le corpus est rejoué comme test sur la toolchain stable.

## Conséquences

- Le décodeur fait une centaine de lignes, sans dépendance hormis `base64` pour la forme texte. Il est facile à auditer et à fuzzer.
- Le format n'est pas un standard : un outil tiers doit l'implémenter d'après cet ADR. Toute évolution impose une nouvelle version, et l'agent refuse les versions inconnues.
- 184 octets, soit 246 caractères, tiennent dans le champ mot de passe RDP avec une marge de 18 octets. Il ne reste que 7 octets pour un éventuel champ futur : une évolution plus large devra raccourcir un champ existant (par exemple l'expiration en durée relative) ou renoncer au champ mot de passe.
- **Passage à la v2 sans transition** : aucun grant v1 n'est déployé ; la v1 est refusée comme toute version inconnue. Le vérificateur de grants ne connaît ni la session ni le compte : comparer la liaison reste à la charge de l'appelant (`Gateway::open_ssh_session` pour SSH).
- Quelqu'un qui peut écrire dans le journal anti-rejeu de l'agent peut effacer des jti et rejouer un grant encore valide. Seuls les droits du fichier protègent contre ça, comme pour la configuration (`CFG-P006`). La consommation par le core réduit ce risque.
- Sous Windows, le renommage atomique ne synchronise pas le dossier (NTFS journalise ses métadonnées) ; sous Unix, le dossier est synchronisé après chaque remplacement.
- libFuzzer n'est pas fiable sous Windows/MSVC (runtime AddressSanitizer de Visual Studio 2019 incompatible, édition de liens impossible sans sanitizer) : le fuzzing se fait sous Linux.
