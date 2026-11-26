# ADR-0025 : Laboratoire décrit en code

- **Statut** : Accepté. Implémenté dans le jalon M2, PR 21 (`m2/lab`).
- **Date** : 2026-11-26

## Contexte

Le jalon M2 se démontre sur de vrais Windows : RDP vers Windows Server 2016 et 2022 membres d'un domaine, Kerberos SPNEGO, LDAPS, agent Windows en *dial-back* dans une zone isolée. Le projet n'a aucun hyperviseur. Il dispose seulement de la CI GitHub du dépôt public.

Contraintes :

- exécuteurs standard gratuits `ubuntu-24.04` : 4 vCPU, 16 Go de mémoire, 6 h au plus par job ;
- aucune image Windows publiée ni conservée en artefact public : les systèmes viennent des ISO d'évaluation officielles de Microsoft (180 jours), téléchargées et vérifiées à chaque construction ;
- aucun mot de passe réel : des comptes de test tirés à chaque exécution ;
- la zone de l'agent n'accepte **aucun flux entrant** et ne sort que vers le core et les cibles ;
- les mêmes descriptions et scripts devront viser plus tard un Proxmox ou un Hyper-V ;
- rien de cet outillage n'entre dans le binaire `ostena`.

## Décision

### QEMU/KVM dans l'exécuteur

Les exécuteurs Linux de GitHub exposent `/dev/kvm` (virtualisation imbriquée). Le job le vérifie (`preflight.sh`) et **échoue explicitement** s'il manque : l'émulation logicielle serait inutilisable pour Windows. Mesures du premier run sur `ubuntu-24.04` : 4 vCPU (Xeon 6975P-C), 15 Gio de mémoire, `/dev/kvm` présent, **89 Gio libres** sur `/` sans nettoyage (125 Gio après suppression des SDK préinstallés, qui prend 127 s). Le nettoyage n'est donc fait que si l'espace libre passe sous 60 Gio.

Machines (Server Core, Standard, évaluation) :

| Machine | Système | Segment | Rôle |
|---|---|---|---|
| `dc01` | Windows Server 2022 | `lab` 10.20.0.0/24 | contrôleur de domaine `lab.ostena.test`, DNS, AC d'entreprise AD CS |
| `srv2016` | Windows Server 2016 | `lab` | membre du domaine, Bureau à distance (NLA) |
| `srv2022` | Windows Server 2022 | `lab` | membre du domaine, Bureau à distance (NLA) |
| `gw2016` | Windows Server 2016 | `dmz` 10.20.1.0/24 | passerelle de l'agent, groupe de travail, zone isolée |

Mémoire totale des invités : 8,5 Gio. La passerelle tourne sous 2016, la version la plus ancienne de la matrice de l'agent.

Matériel virtuel identique pour toutes : q35, disque AHCI avec TRIM, carte Intel e1000 (pilotes inclus dans Windows Server 2016 et 2022 : aucun pilote virtio à télécharger), horloge en UTC et « enlightenments » Hyper-V.

### Images de base, différentielles, en cache privé

1. `fetch-iso.sh` télécharge l'ISO par le lien `fwlink` du centre d'évaluation de Microsoft (`lab/images.json`) et vérifie son **SHA-256** : un écart supprime le fichier et arrête le job.
2. `build-base.sh` choisit dans `install.wim` l'image *Server Core* Standard (index lu par `wiminfo`, pas codé en dur), construit un support de configuration (`autounattend.xml`, `ostena-base.ps1`, `boot.ps1`, `sysprep-unattend.xml`) et démarre l'installation sans intervention. À la première ouverture de session, `ostena-base.ps1` installe la tâche de démarrage `OstenaProvision`, efface le mot de passe d'ouverture automatique, puis **généralise** le système avec `sysprep /generalize /oobe /shutdown` : chaque machine créée depuis l'image reçoit un SID, un nom et un mot de passe propres. La généralisation est indispensable : un membre cloné d'un contrôleur de domaine sans elle aurait le SID du domaine et ne pourrait pas le joindre.
3. Le disque est compressé (qcow2, zstd) et **mis en cache par `actions/cache`**, une entrée par version de Windows. La clé dépend des entrées de la construction (ISO, scripts de base, matériel virtuel) et du trimestre : l'image est reconstruite au moins tous les trois mois, bien avant la fin des 180 jours d'évaluation. Le cache d'Actions n'est lisible que par les workflows du dépôt ; aucune image n'est publiée ni téléversée en artefact.
4. Chaque machine du laboratoire démarre sur un **disque différentiel** qcow2 adossé à l'image de base : création instantanée, quelques Gio d'écriture au plus.

Le mot de passe de construction est tiré pour une construction, ne sort que dans le support de cette construction et dans l'image en cache, et chaque machine le remplace par celui de l'exécution dès son premier démarrage.

### Description séparée du fournisseur

```text
lab/
  machines.json            domaine, segments, règles de sortie de la zone isolée, machines, comptes
  images.json              ISO d'évaluation : lien fwlink, SHA-256, édition
  guest/base/              fichiers de l'image de base (réponses sysprep, tâche de démarrage)
  guest/provision/         provision.ps1 : rôles dc, member, gateway
  tools/labconfig.py       secrets de l'exécution, configuration de chaque machine, règles nftables, lab.json
  tools/labhost.py         service de contrôle du laboratoire, côté hôte
  providers/qemu-ci/       fournisseur QEMU/KVM pour un exécuteur GitHub
```

`machines.json`, `guest/` et `tools/` ne connaissent pas l'hyperviseur. Un fournisseur doit seulement : créer les segments et appliquer l'isolement, créer chaque machine depuis l'image de base avec son **support de configuration** (un CD au nom de volume `OSTENA_CFG` contenant `ostena-vm.json` et `provision.ps1`), faire tourner `labhost.py` sur l'adresse de passerelle de chaque segment. Un fournisseur Proxmox ou Hyper-V reprendra les mêmes ISO, réponses et scripts.

### Provisionnement par la machine elle-même

`boot.ps1`, dans l'image de base, attend la fin de la phase OOBE, copie le support de configuration et lance `provision.ps1`. Toute la logique de rôle est sur ce support : la modifier n'invalide pas le cache des images. `provision.ps1` enchaîne des étapes ; une étape qui demande un redémarrage note l'étape suivante et **redémarre la machine elle-même** (le runner ne pilote aucun redémarrage).

- **Toutes** : mot de passe administrateur de l'exécution, adresse IP fixe, DNS, nom, redémarrage.
- **dc** : forêt `lab.ostena.test` (NetBIOS `LAB`), redémarrage ; puis unité `OU=Ostena`, groupe `ostena-rdp-users`, comptes de test, compte de service `ostena-http` avec le SPN `HTTP/bastion.lab.ostena.test` en AES256 seul et sa *keytab* (`ktpass`), enregistrement DNS `bastion` vers l'hôte ; AC d'entreprise racine **ECDSA P-256 / SHA-256** ; certificat du contrôleur de domaine (LDAPS).
- **member** : Bureau à distance avec NLA, compte local `ostena-local`, jonction au domaine (réessayée tant que le domaine n'est pas prêt : toutes les machines démarrent en même temps), redémarrage ; puis groupe `LAB\ostena-rdp-users` dans « Remote Desktop Users », certificat machine émis par l'AC (modèle `Machine`) installé comme certificat RDP.
- **gateway** : groupe de travail, pare-feu Windows bloquant tout flux entrant, Bureau à distance laissé désactivé.

Chaque machine rend compte au service de contrôle (`POST /report/<nom>`) : étape, état, puis **faits** (empreintes SHA-256 et SHA-1 des certificats RDP et LDAPS, certificat de l'AC, *keytab*). Le journal de provisionnement part aussi sur le premier port série, un fichier de l'hôte : c'est ainsi que l'on suit la construction des images, sans réseau.

### Aucun flux entrant : canal tiré par les machines

Le service de contrôle (`labhost.py`, HTTP sur les ponts du laboratoire) ne fait que recevoir. Pour exécuter une commande sur une machine, l'hôte dépose un script PowerShell dans une file locale ; la machine, une fois prête, interroge `GET /task/<nom>` toutes les 3 s, exécute le script et renvoie le résultat. L'hôte n'ouvre donc **jamais** de connexion vers la zone isolée, y compris pour installer l'agent plus tard (`GET /files/<nom>` sert les paquets). Rien de ce qui arrive par le réseau n'est exécuté par l'hôte.

L'isolement est appliqué par une table nftables `inet ostena_lab` générée depuis `machines.json` :

- vers la zone `dmz` : tout nouveau flux est rejeté, qu'il vienne du segment `lab` ou de l'hôte lui-même (chaîne `output`) ; seuls passent les retours de connexions ouvertes depuis la zone ;
- depuis la zone `dmz` : vers l'hôte, le core (UDP 8443-8444, TCP 8443-8445) et le service de contrôle ; vers les membres, TCP 3389 ; vers le contrôleur de domaine, DNS et Kerberos (53, 88, 464) ; tout le reste est rejeté et compté ;
- aucun segment n'est routé vers Internet.

Les contrôles de fumée le vérifient à chaque exécution : depuis la passerelle, 3389 des membres, 88 du DC et le service de contrôle sont joignables, 445 et 389 ne le sont pas, ni Internet ; depuis l'hôte, une connexion vers la passerelle échoue et le compteur de rejets entrants augmente.

### Point d'entrée : `lab.json`

À la fin, `labconfig.py assemble` écrit `$LAB_WORK/out/lab.json` (mode 0600), dont le chemin est exporté dans `LAB_JSON` : domaine et royaume, adresses de l'hôte par segment, machines (rôle, système, IP, FQDN, certificat RDP ou LDAPS avec ses empreintes), certificat de l'AC (`lab-ca.pem`), comptes avec leurs mots de passe de l'exécution, chemin de la *keytab* du service, durées. Les contrôles de fumée comparent les empreintes annoncées à celles réellement servies sur 3389 (négociation X.224 puis TLS) et 636.

### Workflow

`.github/workflows/lab.yml` se déclenche à la demande, chaque nuit, et par `workflow_call` : un autre workflow fournit une commande `command`, exécutée dans le même job une fois le laboratoire prêt (les machines vivent dans l'exécuteur et ne survivent pas au job). En cas d'échec, seuls des diagnostics sans secret sont téléversés : captures d'écran des consoles, journaux série, comptes rendus de progression, durées ; la collecte refuse de copier un fichier qui contiendrait un mot de passe de l'exécution.

### Licences

L'outillage du laboratoire est libre et **extérieur au produit** : QEMU, xorriso, wimtools, nftables et socat (GPL ou LGPL), Python (PSF). Ce sont des outils exécutés par la CI, comme le compilateur : ils ne sont ni liés ni distribués avec `ostena`, la règle des licences permissives (`deny.toml`) ne s'y applique pas. Python reste exclu en production ; il ne sert ici qu'à l'outillage de test. Windows Server est utilisé sous la licence d'évaluation de Microsoft, sans redistribution.

## Conséquences

- Les tests de bout en bout Windows (RDP, Kerberos SPNEGO, LDAPS, agent Windows en zone isolée) ont une cible réelle sans hyperviseur. Ils lisent `LAB_JSON` et s'enchaînent par `workflow_call`.
- Durée mesurée : **6 min 40 s** du démarrage des machines au laboratoire prêt (domaine, AC, LDAPS, membres joints avec leur certificat RDP), **10 min** pour le job complet avec les images en cache, environ 16 min sans cache (installation d'une image de base : 3 min 40 s). Détail dans [laboratoire.md](../exploitation/laboratoire.md). C'est assez court pour un job de nuit ou à la demande ; il ne tourne pas à chaque PR, dont les tests RDP rapides restent sur le serveur de test d'IronRDP et les exécuteurs Windows (plan M2).
- Les images d'évaluation expirent : la clé de cache trimestrielle les reconstruit. Les machines n'étant jamais activées (pas d'Internet), elles affichent un avertissement de licence sans conséquence sur quelques heures de vie.
- Le cache d'Actions est limité (10 Gio par dépôt par défaut) : les deux images compressées (3,1 et 2,8 Gio) y tiennent, mais d'autres caches volumineux pourraient les évincer ; elles seraient alors reconstruites (environ 6 min de plus).
- Les adresses et ports de la zone isolée sont ceux de `machines.json` : un changement des ports du core se reporte là.
- Un fournisseur Proxmox ou Hyper-V reste à écrire ; il réutilisera `machines.json`, `guest/` et `tools/`.
