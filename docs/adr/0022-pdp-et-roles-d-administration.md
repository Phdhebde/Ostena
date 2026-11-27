# ADR-0022 : PDP compilé en mémoire et rôles d'administration séparés

- **Statut** : Accepté en partie. Jalon M2, PR 10a : crate `ostena-policy` (modèle, compilation, décision, installation, rôles), banc. L'intégration au core (chargement depuis PostgreSQL, migration propre, événements d'audit, rôles en base, option de cumul) est la PR 10b.
- **Date** : 2026-11-26

## Contexte

Au jalon M1, le core décide d'un accès SSH par une requête SQL dans la transaction du grant (ADR-0014) : un droit `access_right` relie **un utilisateur à un compte** d'une ressource, pour un protocole, avec une fin obligatoire. La PR 4a y ajoute les **fonctions** d'un droit (transferts, redirections de ports, d'agent, X11), signées dans les droits du grant (ADR-0004). La PR 9c ajoute les **groupes d'utilisateurs** alimentés par les sources d'identité (`user_group`, `user_group_member`, migration `0009`, ADR-0021).

Le modèle « un droit par utilisateur et par compte » ne tient pas à l'échelle visée : un parc de dizaines de milliers de ressources administré par des équipes. Il faut des autorisations du type **groupe d'utilisateurs × groupe de comptes × protocoles × fonctions**, et des **interdictions** qui priment, pour retirer un accès ou une fonction sans réécrire les autorisations.

Contraintes :

- **latence** : la décision est sur le chemin de l'établissement d'une session (< 5 s au total) et de chaque requête du portail qui liste les cibles autorisées ; critère du plan M2 : **p99 < 1 ms pour 10 000 autorisations et 50 000 ressources** ;
- **empreinte** : la politique tient en mémoire du core, sans base supplémentaire ni moteur externe ; pas de dépendance nouvelle ;
- **sécurité par défaut** : refus par défaut, l'interdiction l'emporte, une erreur ou une politique illisible refuse ;
- **testable seule** : comme les crates protocolaires, sans base ni API, avec des tests de propriétés ;
- **séparation des pouvoirs** : celui qui peut élargir un accès ne doit pas être celui qui lit la trace de cet accès (exigence habituelle d'une évaluation CSPN). Aujourd'hui, le seul rôle d'administration est `admin` (ADR-0020).

## Décision

### La crate `ostena-policy`

Point de décision (PDP) **pur** : ni base, ni API, ni entrée-sortie. Seule dépendance : `thiserror`, déjà dans le binaire. Le core lit la politique dans PostgreSQL, la donne à la crate sous forme d'un `Snapshot`, et installe le résultat compilé.

Alternatives écartées :

- **requête SQL à chaque décision** (l'existant) : avec des groupes des deux côtés, la requête joint quatre tables et sa latence dépend de la charge de la base ; le portail, qui évalue chaque cible du catalogue, multiplierait les requêtes ;
- **moteur de politiques générique** (langage de règles embarqué, ou service externe) : dépendances lourdes, et l'expressivité n'est pas souhaitée : un modèle fermé se vérifie, s'explique à un évaluateur et se teste exhaustivement.

### Modèle

Un `Snapshot` porte une **version** et trois listes :

| Élément | Contenu |
|---|---|
| membres des groupes d'utilisateurs | `(groupe, utilisateur)`, **à plat** : les sources résolvent les groupes imbriqués (ADR-0021) |
| membres des groupes de comptes | `(groupe de comptes, compte)` |
| règles | identifiant, sujet, cible, protocoles, effet, fenêtre de validité |

- **Sujet** : un utilisateur ou un groupe d'utilisateurs. **Cible** : un compte ou un groupe de comptes. Un droit `access_right` de l'ADR-0014 est donc une règle « utilisateur × compte » : il se charge **sans migration**.
- **Protocoles** : un ensemble non vide parmi SSH, RDP, VNC, web (valeurs du grant).
- **Effet** :
  - `Allow { functions, max_session_secs }` : autorise, avec ces fonctions, des sessions de 60 s à 12 h ;
  - `Deny` : refuse l'accès, quelles que soient les autorisations ;
  - `DenyFunctions(f)` : retire ces fonctions, l'accès restant décidé par les autorisations.
- **Fenêtre** `[valid_from, valid_until)`, en secondes Unix. Une autorisation **finit toujours**, 366 jours au plus, comme un droit. Une interdiction peut durer indéfiniment (`u64::MAX`) : la faire durer n'élargit rien.
- Un groupe nommé par une règle et absent des membres est vide.

**Fonctions.** Le bit d'une fonction est celui des droits du grant (ADR-0004) : presse-papiers vers la cible (0) et depuis la cible (1), dépôt (2) et récupération de fichiers (3), redirection de lecteurs (4), d'imprimante (5), audio (6), redirection de ports SSH (7), d'agent SSH (8), X11 (9). Noms : ceux de la PR 4a (`port-forwarding`, `agent-forwarding`, `x11-forwarding`), `upload`, `download`, `clipboard-to-target`, `clipboard-from-target`, `drive-redirection`, `printer-redirection`, `audio-redirection` ; `transfer` et `clipboard` nomment les deux sens.

Chaque protocole n'accorde que les fonctions qui ont un sens pour lui, quoi que dise la règle :

| Protocole | Fonctions possibles |
|---|---|
| SSH | transferts (les deux sens ensemble), redirections de ports, d'agent, X11 |
| RDP | presse-papiers, transferts, lecteurs, imprimante, audio |
| VNC | presse-papiers |
| web | presse-papiers, transferts |

En SSH, un transfert dans **un seul sens** n'est jamais accordé : l'agent ne sait pas séparer les sens de `sftp`, `scp` et `rsync` (ADR-0004, bits 2 et 3 ensemble) ; accorder les deux élargirait la règle, on retire donc les deux.

### Décision

Pour une demande (utilisateur, compte, protocole, fonctions voulues, instant) :

1. pas de politique installée, ou politique invalidée : **refus `POL-E003`** ;
2. on lit **seulement** les règles du compte et celles de ses groupes de comptes, et on garde celles qui portent le protocole, sont valides à l'instant et dont le sujet est l'utilisateur ou l'un de ses groupes ;
3. une **interdiction** s'applique : **refus `POL-E002`**, qui nomme la plus petite règle interdisante ;
4. aucune autorisation : **refus par défaut `POL-E001`** ;
5. sinon, **une seule autorisation est retenue**, dans cet ordre : celle qui porte toutes les fonctions voulues (pour le protocole), puis celle qui finit le plus tard, puis la plus longue session, puis le plus petit identifiant. Les fonctions de plusieurs autorisations **ne s'additionnent pas**, comme pour les droits (ADR-0014, révision de la PR 4a) : l'autorisation retenue est celle que l'audit nomme et que l'ouverture de session vérifie de nouveau ;
6. les fonctions des interdictions de fonctions qui s'appliquent sont retirées ; la décision indique les fonctions voulues mais non accordées (`missing`) et, si des fonctions ont été retirées, la plus petite interdiction de fonctions en cause (`restricted_by`) ;
7. la durée maximale de session est celle de l'autorisation, bornée par le temps restant jusqu'à sa fin.

Le résultat ne dépend pas de l'ordre des listes du `Snapshot` (testé), et la décision **n'alloue pas** (testé avec `dhat`).

### Compilation

`CompiledPolicy::compile` vérifie **toute** la politique avant d'en indexer quoi que ce soit : règle en double, sans protocole, fenêtre vide, autorisation de plus de 366 jours ou de session hors de [60 s, 12 h], interdiction de fonctions vide, liste de plus de 2²⁴ éléments. Une seule erreur refuse la politique entière (`POL-E004`), et la politique en place reste.

Chaque identifiant (UUID, 128 bits) reçoit un index dense ; les relations (groupes d'un utilisateur, groupes d'un compte, règles d'un compte, règles d'un groupe de comptes) sont des tableaux triés, un tableau de décalages et un de données par relation, sans allocation par élément. Une décision coûte deux recherches dans une table de hachage, puis, par règle candidate, une recherche dichotomique dans les groupes de l'utilisateur. La mémoire est **linéaire** dans la taille de la politique : une règle sur un groupe de 50 000 comptes ne coûte qu'une entrée, les appartenances ne sont jamais multipliées par les règles.

### Installation et invalidation

Un `Pdp` tient la politique en place derrière un verrou en lecture-écriture. Une décision prend le verrou en lecture le temps de cloner un `Arc`, puis décide hors du verrou : une installation n'attend jamais une décision.

- **Installation** (`install`) : remplace la politique **en entier**. La version ne recule jamais : une version plus ancienne que la plus haute déjà installée est refusée (`POL-E005`), si bien qu'un rechargement lent qui finit après un plus récent ne ramène pas une ancienne politique. La même version est acceptée de nouveau (rechargement après une invalidation).
- **Invalidation** (`invalidate`) : retire la politique ; tout est refusé (`POL-E003`) jusqu'à la prochaine installation. **Échec fermé.**

Intégration au core (PR 10b) :

- la version est tirée d'une séquence propre aux politiques, incrémentée par chaque changement (règle, droit, groupe, appartenance, utilisateur désactivé) dans la transaction qui le fait ;
- le changement est notifié sur le canal `ostena_registry` (`policy:<version>`, ADR-0014) ; le core relit tout, compile hors du verrou et installe. **Pendant le rechargement, la politique précédente reste en place** : refuser tout pendant chaque rechargement couperait le service à chaque changement ;
- si le rechargement échoue (base injoignable, politique invalide), le core **invalide** et réessaie toutes les 5 s, comme le rejeu des notifications perdues (ADR-0014). Une notification perdue est rattrapée de la même façon : au retour de l'écoute, le core recharge ;
- à la demande de grant, la décision du PDP remplace la recherche du droit en SQL ; la transaction garde ses verrous (ADR-0014). À `session_request`, la décision est **reprise** avec les fonctions signées dans le grant comme fonctions voulues : une autorisation retirée entre-temps donne un refus, des fonctions manquantes `ACC-E010`.

### Codes

| Code | Signification |
|---|---|
| `POL-E001` | aucune autorisation valide : refus par défaut |
| `POL-E002` | une interdiction valide s'applique |
| `POL-E003` | aucune politique installée, ou politique invalidée |
| `POL-E004` | politique invalide : non compilée, la précédente reste |
| `POL-E005` | version plus ancienne que celle en place : non installée |
| `POL-E006` | un même compte cumulerait l'audit et un rôle qui élargit les accès |

Comme pour l'ADR-0014, l'utilisateur refusé ne reçoit que le libellé générique ; le code et la règle vont dans la chaîne d'audit.

### Événements d'audit (PR 10b)

Les décisions sont consignées par les événements d'accès existants (`access.ssh_granted`, `access.ssh_refused`, `access.session_opened`, `access.session_refused` ; ceux du RDP et du navigateur à leur arrivée), avec de nouveaux champs : `pdp_version` (version qui a décidé), `rule_id` (autorisation retenue ou interdiction en cause), `restricted_by`, `functions` et `code` (`POL-E001` à `POL-E003`). Le champ `right_id` reste pour une règle issue d'un droit.

Nouveaux événements :

| Événement | Classe (ADR-0012) | Contenu |
|---|---|---|
| `access_rule.created` | accordant | règle : sujet, cible, protocoles, effet, fenêtre ; une interdiction est **protectrice** |
| `access_rule.revoked` | protecteur | règle |
| `account_group.created`, `account_group.member_added` | accordant | groupe, compte |
| `account_group.member_removed` | protecteur | groupe, compte |
| `policy.installed` | au mieux | version, version remplacée, nombre de règles, d'utilisateurs, de groupes, de comptes, durée de compilation |
| `policy.invalidated` | au mieux | version retirée, raison (`code`) |
| `policy.reload_failed` | au mieux | raison ; agrégé, une fois par minute au plus |

Une décision du portail qui ne fait que lister le catalogue n'est pas auditée une par une (elle n'ouvre rien) ; l'ouverture qui suit l'est.

### Rôles d'administration séparés

Trois rôles (la PR 10b étend la contrainte de `user_role`) :

| Rôle | Pouvoirs |
|---|---|
| `admin` | utilisateurs, groupes et inventaire |
| `policy` | règles d'autorisation et droits |
| `audit` | lecture de la chaîne d'audit, des sessions et de leurs transcripts ; rien d'autre |

**`audit` est incompatible avec `admin` et avec `policy`.** La demande vise le cumul « politique et audit » ; on l'étend à `admin`, parce qu'ajouter un utilisateur à un groupe, ou un compte à un groupe de comptes, **accorde** un accès aussi sûrement qu'une règle : sans cela, la séparation se contourne en changeant de rôle. `admin` et `policy` restent cumulables : ils élargissent tous deux les accès, les séparer ne protège pas l'audit.

- À l'attribution d'un rôle, le cumul est refusé (`POL-E006`, au même titre que `CORE-E012`).
- Au démarrage, les rôles déjà donnés sont vérifiés : un cumul **arrête le core en production** (`POL-E006`), et n'est qu'averti en développement.
- **Option explicite** (décision du mainteneur du 2026-11-27), pour les petites équipes qui ne peuvent pas séparer : `[core.admin] allow_role_cumulation = true`, avec `role_cumulation_justification`, **obligatoire en production** (20 caractères au moins, espaces de début et de fin non comptés ; sinon la configuration est refusée par un code `CFG-V…`, attribué par la PR 10b). Sans l'option, le cumul est refusé en production. Avec elle :
  - elle est journalisée **à chaque démarrage**, avec sa justification (`config.waiver`) ;
  - elle est journalisée **à chaque usage** : chaque attribution d'un rôle cumulé (`user.role_granted`, champ `cumulation`) et chaque action d'administration faite par un compte qui cumule (`admin.role_cumulation_used`, au mieux).

  Justification : la règle générale refuse en production toute option qui affaiblit ; ici, l'interdire sans recours pousserait ces équipes à partager un compte, ce qui détruit l'imputabilité, pire que le cumul. La dérogation est motivée et visible dans l'audit.

La règle d'incompatibilité est dans la crate (`roles`), testée seule ; l'option, la vérification au démarrage et la base sont dans la PR 10b.

### Hors du périmètre v0

Fenêtres horaires récurrentes, groupes de comptes imbriqués, conditions (adresse source, force de l'authentification), approbations et workflows : ils s'ajoutent comme filtres d'une règle sans changer l'ordre de décision. Le PDP ne vit que dans le core ; l'agent applique ce que le grant signe.

## Conséquences

- **Mesures** (`cargo bench -p ostena-policy --bench decision`, machine de développement partagée à 4 cœurs) : 10 000 règles (80 % groupe × groupe de comptes, 10 % utilisateur × compte, 5 % interdictions, 5 % interdictions de fonctions), 50 000 ressources à deux comptes, 5 000 utilisateurs dans 500 groupes (10 groupes chacun), 1 000 groupes de comptes ; 200 000 décisions par le `Pdp` (verrou et clonage compris) : **p50 0,50 µs, p99 0,95 µs**, maximum 55 µs ; aucune allocation. Compilation 36 ms. **Mémoire tenue : 6,5 Mio** (pic de 8,0 Mio pendant la compilation). Le critère (p99 < 1 ms) est tenu avec trois ordres de grandeur de marge. Banc affiché, pas bloquant (ADR-0005).
- Les droits de l'ADR-0014 deviennent des règles comme les autres : une seule logique de décision, testée contre une lecture naïve des règles (propriétés).
- Un changement de politique s'applique en mémoire après un rechargement complet (36 ms de compilation à cette taille, plus la lecture de la base). Pour des politiques beaucoup plus grandes, un rechargement incrémental sera à étudier ; la version monotone le permet sans changer l'interface.
- **Limites connues** :
  - comme un droit (ADR-0014), une règle retirée **ne coupe pas** les sessions ouvertes ; elle empêche tout nouveau grant et toute ouverture avec un grant déjà émis ;
  - entre un changement et l'installation de la politique rechargée, l'ancienne décide encore (de l'ordre de la seconde) ;
  - un compte inconnu du PDP est refusé par défaut : une ressource ajoutée n'est accessible qu'après le rechargement qui suit son ajout.
