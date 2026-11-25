# ADR-0017 : Signature des livrables

- **Statut** : Accepté. Implémenté dans le lot M1, PR 9a, avec une clé de test tirée à chaque exécution de la CI.
- **Date** : 2026-11-25

## Contexte

Un client installe Ostena en environnement isolé, à partir de fichiers copiés à la main : binaires Linux et Windows, SBOM. Il doit pouvoir vérifier, hors ligne et sans outil tiers, que ces fichiers sont ceux que le projet a produits et qu'ils n'ont pas été modifiés en chemin.

Contraintes :

- toute la cryptographie passe par `ostena-crypto`, avec les algorithmes de l'ADR-0009 ;
- aucun outil externe : pas d'OpenSSL, pas d'outil de signature sous licence non permissive ;
- `xtask` reste sans dépendance (ADR-0002) : il ne signe pas lui-même ;
- le jalon M1 demande des binaires signés par la CI, avec une clé de test.

## Décision

### Un manifeste signé

On signe un **manifeste** qui liste l'empreinte de chaque fichier, et non chaque fichier séparément. Une seule signature couvre ainsi un ensemble cohérent : binaires et SBOM d'une même construction.

```text
ostena-release-manifest-v1
<SHA-256, 64 chiffres hexadécimaux minuscules>  <nom>
```

- Une ligne par fichier, **triée** par nom (ordre des octets), chaque ligne terminée par `\n`, sans ligne vide. Après l'en-tête, les lignes sont celles de `sha256sum` : `tail -n +2 manifeste | sha256sum -c` vérifie aussi les empreintes, mais pas la signature.
- Nom : 1 à 128 octets de `A-Z a-z 0-9 . _ + -`, commençant par une lettre ou un chiffre. Pas de répertoire, pas de fichier caché, rien qu'un terminal ou un shell interpréterait.
- 1 à 256 fichiers ; manifeste de 50 Kio au plus.
- **Décodeur strict** : seul l'encodage canonique est accepté, donc `encode(decode(b)) == b`.

### La signature

- **ECDSA P-256 / SHA-256** (ADR-0009), par `ostena_crypto::p256`, sur `ostena/release-manifest/v1\0 ‖ manifeste`. Le préfixe empêche de réutiliser la signature d'un autre message du projet.
- Fichier `<manifeste>.sig`, une ligne : `ostena-release-signature-v1:<kid>:<signature>`. Le `kid` donne en 16 chiffres hexadécimaux les 8 premiers octets du SHA-256 de la clé publique, comme pour les grants et les têtes d'audit. La signature est encodée en base64url sans remplissage, sous sa forme canonique uniquement.
- La clé est une paire P-256 ordinaire, produite par `ostena ca key new` (PEM PKCS#8 en 0600, clé publique `ostena-p256-public-key-v1`).
- La vérification choisit la clé de confiance par son `kid` (16 clés au plus, pour une rotation). Elle vérifie la signature **avant** d'analyser le manifeste, puis l'empreinte de chaque fichier listé. Les fichiers du répertoire que le manifeste ne liste pas sont ignorés.

Alternative écartée : signer chaque binaire dans son format (Authenticode, signature ELF). Cela demande des outils propres à chaque plateforme et laisse les SBOM de côté. Une signature Authenticode pourra s'ajouter plus tard pour Windows, sans remplacer le manifeste.

### Commandes

Elles sont dans le binaire `ostena`, parce que le client vérifie avec l'outil qu'il installe :

```bash
ostena ca key new --key-out release.key --public-out release.pub
ostena release sign --key release.key --out ostena-release.manifest ostena ostena.exe *.cdx.json
ostena release verify ostena-release.manifest --key release.pub [--signature …] [--dir …]
```

- `sign` n'écrase jamais rien. Il écrit le manifeste puis `<manifeste>.sig`, et retire le manifeste si la signature ne peut pas être écrite.
- `verify` sort en 0 si tout est vérifié, en 1 dès qu'il trouve une erreur `REL-E…` et en 3 pour une erreur d'utilisation ou de lecture (manifeste, signature ou clé illisible), comme `ostena audit verify`.

Le binaire vérifie ses pairs mais ne se prouve pas lui-même. En pratique, le client vérifie avec un binaire `ostena` d'une version déjà installée, ou recoupe le manifeste avec `sha256sum`. La première remise de la clé publique passe par un canal de confiance, comme celle de la clé d'audit.

### Codes

| Code | Signification |
|---|---|
| `REL-E001` | manifeste mal formé (en-tête, ligne, empreinte, nom, ordre, doublon, taille) |
| `REL-E002` | fichier de signature mal formé |
| `REL-E003` | manifeste signé par une clé inconnue (`kid` absent des clés de confiance) |
| `REL-E004` | signature du manifeste invalide |
| `REL-E005` | fichier listé absent ou illisible |
| `REL-E006` | fichier modifié : empreinte différente de celle du manifeste |
| `REL-E007` | clé de signature illisible, ou échec de la signature |
| `REL-E008` | manifeste ou signature déjà présent (jamais écrasé), ou écriture impossible |
| `REL-E009` | aucune ou plus de 16 clés de confiance |

### En CI : une clé de test, jetable

Le job `release-sign` reprend le binaire Linux musl, le binaire Windows et les SBOM de la même exécution. Il tire une **clé de test éphémère** avec `ostena ca key new`, signe, détruit la clé privée, vérifie, puis s'assure qu'une copie modifiée est refusée (code 1). L'artefact `ostena-test-signed` contient les fichiers, le manifeste, sa signature et la clé publique de test.

Cette signature prouve l'intégrité de l'artefact, **pas son origine** : n'importe qui peut tirer une telle clé. Nous n'avons pas voulu d'une clé privée de test versionnée, parce que dans un dépôt public elle deviendrait vite une clé « connue » qu'on finit par croire.

## Conséquences

- Un client vérifie un livrable hors ligne avec `ostena release verify` et la clé publique du projet. `sha256sum` reste un recoupement possible.
- La **clé de publication** réelle n'existe pas encore. Elle viendra avec l'industrialisation (lot L15, mises à jour signées) : génération hors ligne en cérémonie, clé privée hors de la CI, publication de la clé publique et de son `kid`. D'ici là, aucun artefact de la CI ne doit être présenté comme signé par le projet.
- La signature reste ECDSA P-256 seule. L'ADR-0009 prévoit ECDSA P-256 + ML-DSA-65 pour les signatures durables. Un manifeste v2 portera les deux signatures quand `ostena-crypto` offrira ML-DSA-65. Le préfixe de domaine et la version du format le permettent sans casser la v1.
- La reproductibilité bit à bit (ADR-0002) n'est pas vérifiée : la signature atteste « ce que la CI a construit », pas « ce que le source produit ».
