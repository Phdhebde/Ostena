# ADR-0005 : Contrôle de périmètre et anti-SSRF

- **Statut** : Accepté
- **Date** : 2026-11-11

## Contexte

Chaque driver (SSH, RDP, VNC, proxy web) ouvre une connexion vers une cible désignée par le core. Si la passerelle se laissait diriger vers n'importe quelle adresse, elle deviendrait un relais vers des cibles qu'elle n'a pas à atteindre : services de métadonnées cloud, boucle locale, ses propres services, l'infrastructure Ostena elle-même. C'est le risque SSRF. Les ruses classiques pour contourner un filtre sont connues : formes numériques ambiguës (`0x7f.1`, `2130706433`), IPv4 cachée dans IPv6 (`::ffff:127.0.0.1`), DNS rebinding (un nom qui change d'adresse entre la vérification et la connexion), noms résolus par des protocoles non authentifiés.

`ostena-scope` est le contrôle unique, appliqué à **tous** les drivers.

## Décision

### Chaîne de traitement

1. **Analyse stricte de la cible**, avant toute résolution (`SCP-E001` à `SCP-E005`) :
   - normalisation en minuscules et suppression d'un point final ;
   - étiquettes LDH (lettres, chiffres, tirets), `_` refusé ;
   - **non-ASCII refusé : pas d'IDNA pour l'instant**. Un nom internationalisé doit être saisi sous sa forme ASCII (`xn--…`). La prise en charge d'IDNA (UTS 46) demandera une dépendance et un ADR ;
   - identifiants de zone IPv6 (`%eth0`) refusés ;
   - `localhost`, `*.localhost` (RFC 6761) et `*.local` (mDNS, non authentifié) refusés par leur nom ;
   - **forme numérique ambiguë** : si la dernière étiquette est numérique (chiffres, ou `0x` suivi d'hexadécimal), la chaîne doit être une IPv4 décimale pointée stricte (4 parties, sans zéro initial, ≤ 255), sinon refus. Cela couvre `0x7f.1`, `2130706433`, `0177.0.0.1` et `127.1`. Aucun nom réel ne se termine par une étiquette numérique.
2. **Résolution unique** par le résolveur du système (`getaddrinfo`), qui respecte le DNS Active Directory, le fichier hosts et les suffixes de recherche du client.
   - Une résolution dure au plus 3 s. Le nombre de résolutions simultanées est borné à 32 : un `getaddrinfo` bloqué continue de compter jusqu'à son retour.
   - Au plus 32 adresses par réponse : au-delà, la cible est refusée plutôt que tronquée.
   - Le résolveur est derrière un trait `Resolver`, remplacé par un faux dans les tests.
3. **Normalisation** de chaque adresse. Sont jugées **comme l'IPv4 qu'elles contiennent** : l'IPv4 mappée `::ffff:a.b.c.d`, l'IPv4 traduite SIIT `::ffff:0:a.b.c.d`, le NAT64 bien connu `64:ff9b::/96` et l'IPv4 compatible `::a.b.c.d`. Seules les règles IPv4 s'appliquent alors ; une règle IPv6 qui couvrirait ces plages est refusée à la compilation (`SCP-E012`).
4. **Décision** : plancher, puis réseaux interdits, puis réseaux autorisés (refus par défaut), puis port.
5. **Épinglage** : **toutes** les adresses renvoyées doivent passer ; une seule refusée entraîne le refus de la cible (`SCP-E011`), sans filtrage silencieux. Le résultat, `PinnedTarget`, ne peut être construit qu'ici. Il contient seulement les adresses vérifiées (au plus 32, dans l'ordre du résolveur) et le nom d'origine, conservé pour SNI, les SPN Kerberos et la validation de certificat. **Le driver se connecte uniquement à ces adresses et ne résout jamais à nouveau**, ce qui ferme la porte au DNS rebinding.

### Plancher non désactivable

Refusé quelle que soit la politique (`SCP-E007`, avec la cause) :

| Plage | Cause |
|---|---|
| `0.0.0.0/8`, `::` | non spécifiée |
| `127.0.0.0/8`, `::1` | boucle locale |
| `169.254.0.0/16`, `fe80::/10` | lien local |
| `224.0.0.0/4`, `ff00::/8` | multicast |
| `255.255.255.255` | diffusion |
| `240.0.0.0/4` | réservée |
| `fec0::/10` | site-local IPv6 (obsolète) |
| `2001::/32` | Teredo : refusé en entier, sans normalisation |
| `2002::/16` | 6to4 : refusé en entier, sans normalisation |
| `64:ff9b:1::/48` | NAT64 à usage local (RFC 8215) ; une option `nat64_prefixes` viendra plus tard |
| adresses des interfaces de la passerelle et leurs adresses de diffusion | adresse propre (`if-addrs`, liste rafraîchie toutes les 60 s) |

Adresses de métadonnées et de services de plateforme cloud, avec leurs sources :

| Adresse | Service | Source |
|---|---|---|
| `169.254.169.254` | AWS, Azure, GCP, OCI | [AWS](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instancedata-data-retrieval.html), [Azure](https://learn.microsoft.com/en-us/azure/virtual-machines/instance-metadata-service), [GCP](https://docs.cloud.google.com/compute/docs/metadata/querying-metadata), [OCI](https://docs.oracle.com/en-us/iaas/Content/Compute/Tasks/gettingmetadata.htm) |
| `fd00:ec2::/64` | AWS IMDS en IPv6 (`fd00:ec2::254`) ; tout le /64 par prudence pour les services AWS voisins | [AWS](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instancedata-data-retrieval.html) |
| `fd20:ce::254` | GCP, instances IPv6 seulement | [GCP](https://docs.cloud.google.com/compute/docs/metadata/querying-metadata) |
| `100.100.100.200` | Alibaba Cloud (hors lien local : dans 100.64.0.0/10) | [Alibaba Cloud](https://www.alibabacloud.com/help/en/ecs/user-guide/view-instance-metadata) |
| `168.63.129.16` | Azure WireServer (agent, DNS, DHCP, sondes) | [Azure](https://learn.microsoft.com/en-us/azure/virtual-network/what-is-ip-address-168-63-129-16) |
| `192.0.0.192` | Oracle Compute Classic | [Oracle](https://docs.oracle.com/en/cloud/iaas-classic/compute-iaas-cloud/stcsg/retrieving-instance-metadata.html) |

Les réseaux privés (RFC 1918), CGNAT, documentation ou banc d'essai ne sont **pas** dans le plancher : c'est le rôle de la politique.

**Plancher « infrastructure Ostena »** : les adresses du core, du coffre-fort, de l'audit et de PostgreSQL, fournies par la configuration de l'agent, sont refusées comme cibles quelle que soit la politique (`SCP-E016`).

**Exception** : une exception au plancher (statique, adresses propres et infrastructure) n'existe **qu'en mode développement**. Elle doit porter une raison, est refusée en production (`SCP-E013`) et est journalisée à la compilation (`scope.weakening`) puis à chaque usage (`scope.floor_exception_used`). Elle lève le plancher, pas la politique.

### Politique

- Une politique par groupe de passerelles :
  - **règles autorisées** : des réseaux et des **ports par règle** ;
  - **règles interdites** : des réseaux, qui l'emportent toujours.
- **Refus par défaut** : sans règle autorisée, rien ne passe. Le port 0 est toujours refusé.
- **Format** : structures `serde` strictes (`deny_unknown_fields`), intégrables dans la configuration TOML de l'agent, en attendant que le core pousse la politique. Les CIDR sont stricts : `10.0.0.1/8` (bits d'hôte non nuls) est refusé comme probable faute de frappe. Les ports s'écrivent `"22"` ou `"8000-8100"`.
- **Compilation** : la politique est convertie en intervalles disjoints triés (`u128` par famille). Les règles autorisées qui se chevauchent fusionnent leurs ports. La décision fait quelques recherches dichotomiques, **sans allocation**, ce que prouve un test avec `dhat`. Toutes les erreurs de politique sont rapportées d'un coup. La politique est bornée à 100 000 réseaux.

### Noms courts (sans point)

**Refusés par défaut** (`SCP-E014`). Sous Windows, un nom sans domaine que le DNS ne résout pas est ensuite cherché par **LLMNR** et **NetBIOS** : ces protocoles diffusent la question sur le réseau local, sans authentification, et n'importe quelle machine du segment peut répondre. Un attaquant présent sur le segment de la passerelle peut ainsi détourner la connexion, et récupérer des authentifiants NTLM si le protocole s'y prête.

`allow_short_names = true` est un **affaiblissement** :
- en développement, accepté et journalisé (`scope.weakening`) ;
- en production, refusé (`SCP-E015`) **sauf** avec `short_names_justification`, qui est journalisée à chaque démarrage. Chaque usage est aussi tracé (`scope.short_name_used`).

La fiche d'exploitation recommande de désactiver LLMNR et NetBIOS sur l'hôte de l'agent.

### Codes et audit

| Code | Refus |
|---|---|
| `SCP-E001` | cible mal formée (syntaxe, longueur, `_`, port) |
| `SCP-E002` | nom non-ASCII |
| `SCP-E003` | forme numérique ambiguë |
| `SCP-E004` | nom réservé (`localhost`, `.local`) |
| `SCP-E005` | identifiant de zone IPv6 |
| `SCP-E006` | port 0 ou non autorisé pour ce réseau |
| `SCP-E007` | plancher (la cause est précisée) |
| `SCP-E008` | réseau interdit |
| `SCP-E009` | aucun réseau autorisé |
| `SCP-E010` | résolution en échec, vide, trop grande, hors délai, trop de résolutions simultanées |
| `SCP-E011` | une adresse résolue est refusée (la cause précise est jointe) |
| `SCP-E012` | politique invalide |
| `SCP-E013` | exception au plancher en production |
| `SCP-E014` | nom court refusé |
| `SCP-E015` | noms courts en production sans justification |
| `SCP-E016` | adresse de l'infrastructure Ostena |

Événements :
- **`scope.refused`** : code, cible demandée, adresse jugée (normalisée), adresse d'origine si elle cachait une IPv4, identifiant de la règle (`floor:cloud-metadata`, `deny[2]`, `infrastructure[0]`, `default-deny`, `port`…) et groupe de passerelles. Il est prêt pour l'audit ;
- **`scope.pinned`** : adresses retenues ;
- **`scope.weakening`**, **`scope.floor_exception_used`**, **`scope.short_name_used`** ;
- **`scope.local_addresses_failed`** : la liste des adresses de la passerelle n'a pas pu être rafraîchie ; l'ancienne est conservée.

### Vérification

- **Tests unitaires** : un par règle et par code.
- **Propriétés proptest** :
  - aucune adresse du plancher n'est jamais acceptée, même avec une politique qui autorise `0.0.0.0/0` et `::/0`, y compris sous ses formes IPv6 ;
  - les adresses de la passerelle et de l'infrastructure ne sont jamais acceptées ;
  - une IPv4 et ses formes IPv6 donnent toujours la même décision ;
  - la politique compilée décide comme un oracle naïf, ce qui inclut « l'interdit l'emporte ». Ce test a révélé un défaut de compilation (deux réseaux imbriqués d'une même règle), corrigé et couvert par un test de régression.
- **Deux cibles de fuzz** (`scope_target`, `scope_policy`) ; leurs corpus sont rejoués sur la toolchain stable.
- **Banc** (`cargo bench -p ostena-scope`) : 1 000 règles autorisées et 100 interdites, environ 10 à 50 ns par décision sur le poste de développement.

## Conséquences

- Tous les drivers dépendront d'`ostena-scope` et ne recevront qu'un `PinnedTarget`. Une connexion ouverte autrement doit être refusée en revue.
- Le proxy web devra repasser chaque redirection HTTP par `ostena-scope`.
- Le résolveur de l'OS ne s'annule pas : un `getaddrinfo` bloqué occupe un thread jusqu'à son retour, d'où la borne sur les résolutions simultanées.
- Les noms Active Directory sans domaine ne fonctionnent pas sans justification explicite : les cibles doivent être déclarées par leur nom complet.
- Le banc est affiché en CI sans seuil bloquant : **la règle des 10 % de CLAUDE.md reste à brancher** quand une machine de référence stable sera disponible (les runners partagés sont trop bruyants).
- Pas d'IDNA : les noms internationalisés doivent être saisis en ASCII (`xn--…`).
- La liste des adresses de la passerelle peut avoir jusqu'à 60 s de retard sur un changement d'interface.
