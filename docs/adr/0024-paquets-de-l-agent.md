# ADR-0024 : Paquets de l'agent

- **Statut** : Accepté. Implémenté dans le jalon M2, PR 18, avec des certificats et une clé de test tirés à chaque exécution de la CI.
- **Date** : 2026-11-26

## Contexte

L'agent passerelle s'installe sur Windows Server 2016 à 2025 et sur Debian 12 et 13 (ADR-0007). Jusqu'ici, l'administrateur copiait le binaire, écrivait la configuration, enrôlait l'agent puis lançait `ostena agent install`. Un client déploie pourtant ses serveurs avec ses outils : stratégies de groupe (GPO), Intune ou SCCM sous Windows, `apt` et sa gestion de configuration sous Debian. Il lui faut :

- un **MSI** qui s'installe sans interaction (`msiexec /qn`), avec ses paramètres en ligne de commande, et un **`.deb`** ;
- une installation qui ne duplique pas ce que fait déjà le binaire (compte, ACL, unité, service) : une seule logique, testée une fois ;
- des paquets construits **hors ligne**, avec des outils dont la licence est acceptable, et **signés** ;
- la preuve, en CI, que le paquet installé démarre, n'écoute sur aucun port quand l'agent ne fait que se connecter au core (*dial-back*), et que son plan de contrôle reste fermé à un utilisateur non administrateur.

## Décision

### `ostena agent setup` : toute la logique dans le binaire

Les paquets posent les fichiers, puis appellent une seule commande, non interactive et qu'on peut relancer :

```bash
ostena agent setup --core-address core.exemple:8443 --gateway-group <UUID> \
  --root-ca root.pem --root-fingerprint <SHA-256 du procès-verbal> \
  [--enrollment-address hôte:port] [--token-file jeton.txt] [--log fichier] [--quiet]
```

1. **Racine** : le certificat donné par `--root-ca` est comparé à l'empreinte SHA-256 du procès-verbal de la [cérémonie](../exploitation/ceremonie-racine.md) (64 chiffres hexadécimaux, majuscules, `:` et espaces admis). `--root-fingerprint` est obligatoire avec `--root-ca`. Si l'empreinte ne correspond pas, rien n'est écrit (`AGT-E011`). La racine est copiée à côté de la configuration (`root.pem`). Une racine **différente** déjà en place n'est jamais remplacée (`AGT-E011`). Donnée seule, l'empreinte vérifie la racine en place.
2. **Configuration** : si le fichier existe, il est conservé. Les paramètres donnés doivent alors correspondre à son contenu (`agent.core_address`, `agent.gateway_group`) : sinon, la commande refuse (`AGT-E012`) plutôt que d'ignorer en silence ce que le déploiement demande. Sinon, elle écrit une configuration minimale de **production**, vérifiée comme le fait `install` avant d'être écrite :
   - aucun serveur SSH natif (`[agent.ssh]` absent), donc **aucun port en écoute** ;
   - clé, certificat et journal anti-rejeu dans le dossier d'état (`C:\ProgramData\Ostena\state`, ou `/var/lib/ostena` qui est le `StateDirectory` de l'unité, seul chemin inscriptible sous `ProtectSystem=strict`) ;
   - sous Windows, journal dans `state\agent.log` (le service n'a pas de console) ; sous Linux, sortie standard, donc journald.

   Une nouvelle configuration exige l'adresse du core, le groupe et une racine (`AGT-E012`, `AGT-E011`).
3. **Enrôlement** : si l'agent n'a pas encore de certificat et qu'un fichier de jeton est donné, il est enrôlé comme par `ostena agent enroll` (codes `TUN-E0xx`). Sans jeton, la commande avertit et continue. L'agent démarre alors sans lien avec le core, et l'administrateur l'enrôlera plus tard. Le jeton n'apparaît jamais sur une ligne de commande, seulement le chemin de son fichier.
4. **Service** : `ostena agent install` (ADR-0007) : compte, droits, unité ou service NT, démarrage.

Une valeur vide compte comme absente : le MSI passe toutes ses propriétés, renseignées ou non. `--log` ajoute chaque message à un fichier, parce qu'une action personnalisée du MSI n'a pas de console. Ce fichier ne contient que des chemins, des empreintes et des erreurs, jamais de secret.

| Code | Erreur |
|---|---|
| `AGT-E011` | racine refusée : empreinte absente, invalide ou différente, racine absente pour une nouvelle configuration, ou autre racine déjà en place |
| `AGT-E012` | configuration refusée : paramètres manquants pour l'écrire, ou configuration en place en désaccord avec les paramètres |

### Service Windows : démarrage automatique différé

`ostena agent install` inscrit désormais le service en **démarrage automatique différé** (`AUTO_START (DELAYED)`), par `set_delayed_auto_start` de `windows-service`. L'agent démarre ainsi une fois les services du démarrage en place (réseau, résolution de noms, domaine), sans leur disputer la machine. Il n'en a pas besoin plus tôt : son lien avec le core réessaie de toute façon. La reprise sur échec reste celle de l'ADR-0007 (3 redémarrages après 5 s, compteur remis à zéro après 600 s). Le job `windows` vérifie le nouveau type de démarrage (`sc.exe qc`).

### MSI : wixl (msitools), sur Linux

| Outil | Licence | Ce qu'il demande | Verdict |
|---|---|---|---|
| WiX v3 | MS-RL | Windows et .NET Framework 3.5 ; branche en fin de vie | écarté |
| WiX v4 et suivants | MS-RL | SDK .NET et paquets NuGet téléchargés au build ; les binaires officiels des versions récentes sont en plus soumis à des conditions de financement de la maintenance pour les organisations à revenus | écarté |
| **wixl** (msitools) | LGPL-2.1-or-later | Linux, paquet `wixl` des archives Debian et Ubuntu | **retenu** |

La liste de licences de CLAUDE.md porte sur les dépendances liées au produit. Un outil de construction n'est pas lié au produit, et le MSI qu'il produit n'est pas une œuvre dérivée de l'outil : c'est déjà le cas de `dpkg`, de `gcc` ou de `musl-gcc`. MS-RL aurait donc été acceptable. wixl l'emporte parce qu'il tourne sur Linux, à côté de la construction du `.deb`, depuis un paquet de distribution qu'un miroir local fournit hors ligne, sans .NET ni NuGet.

wixl ne connaît qu'une partie du schéma WiX v3 : pas d'interface graphique, et nous n'utilisons pas `ServiceInstall`, puisque le service est inscrit par le binaire. `packaging/windows/build-msi.sh` vérifie après la construction, avec `msiinfo`, les tables qui comptent : types des actions personnalisées et séquence.

Ce que contient le paquet (`packaging/windows/ostena-agent.wxs`) :

- **Fichiers** : `ostena.exe` et `LICENSE.txt` dans `C:\Program Files\Ostena`, x64, installation par machine, aucune interface.
- **Propriétés publiques** : `COREADDRESS`, `GATEWAYGROUP`, `ENROLLMENTADDRESS`, `ROOTCAFILE`, `ROOTFINGERPRINT`, `ENROLLTOKENFILE`.
- **Actions personnalisées** différées, exécutées en SYSTEM (`Impersonate="no"`), qui appellent le binaire installé : par sa ligne de la table `File` pour `setup` (type 3090), par une propriété posée depuis son dossier pour `uninstall` (type 3122), parce qu'à la désinstallation Windows Installer refuse de résoudre un fichier en cours de retrait (erreur 2731) :
  - après `InstallFiles` : `ostena agent setup --quiet --log C:\ProgramData\Ostena\setup.log …` à l'installation, à la réparation et à la mise à jour. Un échec fait échouer l'installation (1603) ;
  - si la première installation échoue, l'action d'annulation (*rollback*) lance `ostena agent uninstall` tant que `ostena.exe` est encore là. Une réparation qui échoue laisse l'agent en place tourner ;
  - avant `RemoveFiles`, à la désinstallation : `ostena agent uninstall`.
- **Mise à jour** majeure seulement. Chaque construction a un nouveau `ProductCode`, et une même version se remplace (reconstruction). L'ancienne version est retirée tôt (`RemoveExistingProducts` juste après `InstallInitialize`) : son action désinscrit le service, puis la nouvelle version refait `setup` avec la configuration en place. Une version plus récente installée bloque une rétrogradation.
- Le **Restart Manager** est désactivé (`MSIRESTARTMANAGERCONTROL=Disable`) : c'est notre action qui arrête le service avant le remplacement des fichiers.
- **Désinstallation** : le service et le programme sont retirés. `C:\ProgramData\Ostena` (configuration, racine, clé, état) est conservé, comme avec `ostena agent uninstall`.
- Condition : Windows 64 bits, NT 6.3 ou plus tel que Windows Installer le voit (Windows Server 2016 se présente ainsi à un MSI sans manifeste).

**Déploiement** :

```text
msiexec /i ostena-agent-<version>-x64.msi /qn /l*v install.log ^
  COREADDRESS=core.exemple:8443 GATEWAYGROUP=<UUID> ^
  ROOTCAFILE=\\serveur\ostena\root.pem ROOTFINGERPRINT=<SHA-256> ^
  ENROLLTOKENFILE=\\serveur\ostena\jetons\GW01.txt
```

- **Intune ou SCCM** : application Win32 avec cette ligne de commande ; désinstallation par `msiexec /x {ProductCode} /qn`.
- **GPO** : une GPO d'installation logicielle ne passe pas de propriété en ligne de commande. On copie d'abord `ostena.toml` et `root.pem` dans `C:\ProgramData\Ostena` par les préférences de la GPO, puis on affecte le MSI : `setup` garde la configuration en place. La deuxième voie est une transformation (`.mst`) qui porte les propriétés.
- **Jeton** : il est à usage unique, donc il en faut un par machine. Une GPO ne sait pas en distribuer un par machine. Dans ce cas, l'agent s'installe sans jeton, puis on l'enrôle par un script ou à la main (`ostena agent enroll`, puis redémarrage du service).

### `.deb` : dpkg-deb

`packaging/debian/build-deb.sh` construit le paquet avec `dpkg-deb` seul, à partir du binaire musl statique de la release, celui que signe le manifeste. `cargo-deb` (MIT) est écarté : ce serait un outil de plus à récupérer sur crates.io, et il reconstruit le binaire au lieu d'empaqueter celui que la CI a vérifié. La construction est reproductible : propriétaire `root:root`, dates fixées à `SOURCE_DATE_EPOCH` (date du commit), compression xz. Le job `package` construit le paquet deux fois et compare les deux résultats.

- **Paquet `ostena-agent`** : `/usr/bin/ostena`, `/usr/share/doc/ostena-agent/copyright`. Dépendances : `systemd (>= 252)` (Debian 12, ADR-0007) et `passwd` (`useradd`). Le jour où un paquet du core existera, le binaire passera dans un paquet commun, avec `Replaces`/`Breaks`.
- **`postinst`** (relançable) :
  - crée l'utilisateur système `ostena` s'il n'existe pas, avec les mêmes options que `install` ;
  - sur une mise à jour d'un agent installé, réécrit l'unité pour le nouveau binaire et redémarre le service (`ostena agent install`) ;
  - sinon, affiche la commande `ostena agent setup` à lancer. Il ne démarre rien tant que l'agent n'est pas configuré : il n'a pas de jeton.
- **`prerm`** : `ostena agent uninstall` à la suppression (`remove`). Lors d'une mise à jour, le service continue de tourner.
- **`postrm`** : `purge` retire ce que `setup` et le service ont écrit (configuration, racine, `/var/lib/ostena` avec l'identité de l'agent). L'utilisateur système est gardé : la politique Debian ne réutilise pas un uid.
- **L'unité** reste celle que génère `ostena agent install` dans `/etc/systemd/system`. Elle n'est pas livrée par le paquet dans `/usr/lib/systemd/system` : une seule source pour l'unité durcie (`systemd_unit`, ADR-0007), et pas deux unités qui se masquent. En contrepartie, `dpkg -S` ne connaît pas l'unité. `prerm` et `postrm` la retirent.

### Signatures

- **Manifeste de l'ADR-0017** : le job `release-sign` signe désormais aussi le `.deb`, le MSI et les certificats publics de test. `ostena release verify` vérifie donc les paquets hors ligne, avec la clé de test de l'exécution.
- **Authenticode** (Windows) : `ostena.exe` puis le MSI sont signés en ECDSA P-256 / SHA-256 (ADR-0009) par `signtool`, l'outil du SDK Windows présent sur l'exécuteur. Le certificat est **de test** : il est tiré dans le job, sa clé est non exportable et détruite à la fin du script (`packaging/windows/sign-test.ps1`), seul le certificat public est gardé. Il y en a donc deux : l'un pour l'exécutable (job `windows`), l'autre pour le MSI (job `msi-sign`), parce qu'une clé de test ne quitte jamais son job. Il n'y a pas d'horodatage : la signature est faite hors ligne, et le certificat n'est que de test. `osslsigncode` est écarté (OpenSSL, GPL), comme dans l'ADR-0017.
- **Debian** : pas de signature GPG du `.deb` : `dpkg` ne vérifie pas `debsigs` par défaut. Un dépôt `apt` signé viendra avec le lot L15.
- Comme dans l'ADR-0017, ces signatures prouvent l'intégrité, **pas l'origine**. Le certificat de signature de code et la clé de publication réels viendront avec le lot L15. D'ici là, aucun paquet de la CI n'est présenté comme signé par le projet.

### Matrice d'installation en CI

| Job | Où | Ce qui est vérifié |
|---|---|---|
| `package` | Ubuntu 24.04 | `.deb` reproductible, MSI construit et ses tables contrôlées |
| `msi-sign` | Windows Server 2025 | signature du MSI, refus d'une copie modifiée |
| `install-windows` | Windows Server 2022 et 2025 | `tests/packaging/windows-msi.ps1` contre un core de test |
| `install-debian` | conteneurs Debian 12 et 13, systemd en PID 1 | `tests/packaging/debian-install.sh` contre un core de test |
| `lab-agent` | laboratoire, `gw2016` (Windows Server 2016) | le même script Windows, sans core |

Le core de test (exemple `test_core` d'`ostena-tunnel`, construit par `cargo xtask footprint`) délivre une identité d'agent, qui tient lieu d'enrôlement, et sert le lien. Sur chaque système, les jobs vérifient :

- les signatures (Authenticode valide, clé ECDSA) ;
- l'installation silencieuse avec les paramètres, et le refus d'une mauvaise empreinte (Debian) ;
- le service actif : démarrage différé, 3 redémarrages, compte virtuel et SID restreint sous Windows ; droits des fichiers sous Debian ;
- `status` : **connecté au core** ;
- **aucun port en écoute** :
  - aucune socket TCP en écoute appartenant à l'agent (`Get-NetTCPConnection -State Listen -OwningProcess`, `ss -ltnp`) ;
  - pour l'UDP, au plus une socket : celle du client QUIC du lien, sur un port éphémère, qui n'a pas de configuration serveur et n'accepte donc aucune connexion. Les nouveaux ports TCP en écoute de l'hôte sont aussi affichés ;
- **plan de contrôle refusé à un non-administrateur** :
  - Windows : un utilisateur local créé pour le test ouvre le pipe en se faisant passer pour lui ; l'accès est refusé ;
  - Debian : `runuser -u nobody -- ostena agent status` échoue avec `AGT-E007` à `E009` sans rien lire, et le socket n'est même pas visible ;
- une réparation (`msiexec /i … REINSTALL=ALL`) ou un second `setup` qui ne changent rien, puis un paramètre contradictoire refusé sans toucher à l'agent en place ;
- la réinstallation (`dpkg -i` à nouveau) ;
- la désinstallation : service et programme retirés, configuration conservée. Sous Debian, la purge retire tout.

### Windows Server 2016 dans le laboratoire

Le job `lab-agent` appelle le workflow réutilisable du laboratoire (`lab.yml`, ADR-0025) chaque semaine et à la demande. Il reste hors de `ci-ok`, parce que le laboratoire prend des heures. `lab.yml` reçoit pour cela une entrée `artifacts` : les artefacts de l'exécution appelante qu'il télécharge avant la commande, sous `$LAB_ARTIFACTS`. La commande est :

```bash
bash lab/agent-msi.sh "$LAB_ARTIFACTS/ostena-test-signed" gw2016
```

Le script vérifie d'abord le manifeste signé. Il tire ensuite une racine propre à l'exécution (`ostena ca root init`, laboratoire seulement), dépose le MSI, les certificats de test et les scripts dans le dossier servi par le service de contrôle, puis fait exécuter `windows-msi.ps1` à la passerelle `gw2016` de la zone isolée par `lab.sh exec`. Aucun core ne répond encore dans le laboratoire. L'agent est donc installé sans enrôlement, et son lien reste « non connecté » vers l'hôte, seule sortie autorisée. Les autres vérifications s'appliquent sous Windows Server 2016 : démarrage différé, compte virtuel, SID restreint, aucun port en écoute, pipe refusé, réparation, désinstallation. Elles remplacent l'essai manuel S5 pour ces points.

## Conséquences

- L'ADR-0007 change sur un point : le service Windows démarre en automatique différé.
- Le MSI et le `.deb` n'ont aucune logique propre. Une correction de l'installation se fait dans le binaire et vaut pour les deux paquets et pour l'installation manuelle.
- Une mise à jour majeure qui échoue laisse le service désinscrit, parce que l'ancienne version a été retirée avant. On relance l'installation, ou `ostena agent install`.
- Une GPO ne peut pas distribuer un jeton par machine : avec une GPO, l'enrôlement se fait après l'installation.
- L'adresse du mainteneur du `.deb` est provisoire (`maintainers@ostena.invalid`) jusqu'au lot L15.
- Sous Windows Server 2016, le lien avec le core n'est vérifié qu'une fois un core installé dans le laboratoire. L'essai manuel S5 reste nécessaire pour le jeton du processus, le squat du pipe et les redémarrages bornés.
- Le jour où le certificat de signature réel existe (lot L15), seul `sign-test.ps1` est remplacé : les paquets et les tests ne changent pas.
