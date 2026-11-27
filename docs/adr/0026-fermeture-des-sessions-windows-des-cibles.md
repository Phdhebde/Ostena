# ADR-0026 : Fermeture des sessions Windows des cibles RDP

- **Statut** : Proposé
- **Date** : 2026-11-27
- **Complète** : ADR-0019 (driver RDP)

## Contexte

En fin de session, le driver RDP envoie la déconnexion MCS (*Disconnect Provider Ultimatum*) et ferme le transport. Pour Windows, c'est une **déconnexion** : la session reste ouverte sur la cible, programmes et identifiants compris. La connexion suivante sur le même compte cible s'y **rattache** (comportement par défaut, une session par utilisateur).

Conséquence constatée en CI : une session Restricted Admin, qui ne transmet aucun secret à la cible, a repris la session ouverte juste avant en délégation du mot de passe. Elle disposait donc du mot de passe délégué en mémoire (identifiants réseau de la session) et des fenêtres de l'administrateur précédent. C'est un défaut de sécurité : l'isolement entre deux sessions, deux administrateurs et deux modes d'authentification n'existe plus. La CI a été contournée par un compte par mode (#75). Les réglages de la cible `fResetBroken` et `MaxDisconnectionTime` (1 s) n'y ont rien changé.

Ce que permet le protocole ([MS-RDPBCGR]) :

- le client n'a **aucune PDU de fermeture de session** (*logoff*) ;
- la *Shutdown Request PDU* (2.2.2.1) ne ferme rien : le serveur répond par la *Shutdown Request Denied PDU* dès qu'un utilisateur est connecté à la session (3.3.5.4.1), et la fin de la connexion ne fait que déconnecter ;
- en revanche, le serveur annonce l'identifiant de la session ouverte dans sa notification d'ouverture (*Save Session Info PDU*, 2.2.10.1, `TS_LOGON_INFO` et `TS_LOGON_INFO_VERSION_2`), que le client demande (`INFO_LOGONNOTIFY`, déjà posé par le connecteur).

Agir sur la session par des frappes simulées (menu de fermeture) ou un shell de remplacement serait fragile et contournable. La fermeture passe donc **hors de RDP**, par l'interface de gestion des sessions Bureau à distance de la cible (API WTS de Windows, RPC sur les canaux nommés de la cible). Aucun agent n'est installé sur la cible.

## Décision

### 1. En fin de session, l'agent ferme la session Windows

Après la fin de la boucle de session, quelle qu'en soit la cause (arrêt demandé, fin par la cible, erreur), l'agent :

1. reprend l'identifiant de session lu dans la *Save Session Info PDU* ;
2. ouvre une vue sur les sessions de la cible (adresse épinglée, identifiants du compte, section 4) ;
3. attend au plus 3 s que la cible voie cette session déconnectée, puis la ferme (`WTSLogoffSession`, en attendant la fin de la fermeture) ; si elle a déjà disparu (l'utilisateur s'est déconnecté lui-même), rien à faire ;
4. sans identifiant (notification absente), ferme toutes les sessions **déconnectées** du compte.

Une session restée tenue par une connexion après le délai (une autre connexion l'a reprise) n'est **pas** fermée : l'échec est journalisé (`RDP-E019`) et la session suivante sera refusée (section 2). La fermeture est bornée à 20 s ; `close()` du driver l'attend.

### 2. Avant une session, l'agent ferme les sessions laissées, ou refuse

Avant la connexion TCP, l'agent liste les sessions de la cible et retient celles du compte (même nom d'utilisateur, et même domaine si le compte en nomme un, sans tenir compte de la casse) :

- une session du compte **tenue par un client** (états *Active*, *Connected*, *ConnectQuery*, *Shadow*) : la nouvelle connexion la reprendrait. **Refus** (`RDP-E018`), sans rien fermer ;
- toute autre session du compte (déconnectée, en cours de réinitialisation…) est **fermée**, puis l'agent vérifie qu'aucune session déconnectée du compte ne reste ;
- toute impossibilité (pas de mécanisme sur l'agent, identifiants refusés, cible injoignable par RPC, fermeture refusée) : **refus** (`RDP-E019`).

C'est le comportement par défaut, le plus sûr. Le temps passé est mesuré dans la phase `sessions` du bilan de connexion (`ConnectReport`), à part de l'établissement RDP ; quand il n'y a rien à fermer, c'est une liste par RPC (quelques allers-retours).

### 3. Une seule option d'affaiblissement, refusée en production

```toml
[rdp]
disconnected_sessions = "logoff"   # défaut ; "keep" : CFG-P022, refusé en production
```

`keep` désactive les sections 1 et 2 : les sessions restent déconnectées et une connexion suivante peut s'y rattacher. Il est refusé à la validation de la configuration en production (`CFG-P022`), refusé aussi par le driver (`RDP-E019`), et journalisé à chaque session en développement (`rdp.session_cleanup_skipped`). Il sert aux essais sur une machine sans gestion à distance des sessions.

### 4. Mécanisme : API WTS de l'agent Windows

- `ostena-platform::wts` (seule crate où vit l'`unsafe`, chaque bloc commenté `SAFETY` et testé sous Windows) : `WTSOpenServerW`, `WTSEnumerateSessionsExW` (niveau 1 : identifiant, état, utilisateur, domaine), `WTSLogoffSession`, `WTSCloseServer`. Aucune nouvelle crate : `windows-sys`, déjà présente, avec la fonctionnalité `Win32_System_RemoteDesktop`.
- **Identifiants** : le fil qui travaille emprunte un jeton `LOGON32_LOGON_NEW_CREDENTIALS` du compte cible (`LogonUserW`) ; ces identifiants ne servent qu'à l'authentification sortante, jamais à une ouverture de session locale sur l'agent. Le mot de passe est relu dans la source des secrets à chaque usage, converti dans un tampon effacé après l'appel. Le compte est celui de la session : un administrateur de la cible (exigé par le Restricted Admin) peut lister et fermer ses sessions ; un compte non administrateur doit en avoir reçu le droit sur l'écouteur RDP, sinon la session est refusée.
- **Fil dédié** : l'emprunt d'identité est lié au fil. Chaque opération tourne sur un fil créé pour elle, qui se termine avec elle : un échec de `RevertToSelf` ne peut pas donner cette identité à une autre tâche.
- **Périmètre** : la vue est ouverte sur l'**adresse épinglée** par le contrôle de périmètre (ADR-0005), jamais sur un nom que Windows résoudrait lui-même.
- **Domaine** : `DOMAINE\compte` tel quel ; `compte@royaume` en nom principal, sans domaine ; un compte local de la cible s'authentifie dans le domaine de la machine (premier label de son nom DNS dans l'inventaire).
- **Agent Debian** : l'API WTS n'existe pas. Réimplémenter l'interface RPC de gestion des sessions ([MS-TSTS]) sur SMB 2 et DCE/RPC est hors de portée de ce correctif. La fermeture y est donc **impossible** : par défaut, la session est refusée (`RDP-E019`). En production, un agent Debian ne peut pas ouvrir de session RDP tant qu'un mécanisme n'existe pas.
- **Côté driver** (`ostena-rdp::target_sessions`) : la règle (quelles sessions fermer, quand refuser) est indépendante du mécanisme (trait `SessionControl`), testée sous Linux avec une cible simulée.

### 5. Défense en profondeur : stratégie des cibles

La fermeture par l'agent ne couvre pas un agent arrêté brutalement ni une coupure réseau entre la fin de session et la fermeture. Les cibles doivent donc aussi fermer elles-mêmes les sessions déconnectées. **Prérequis documenté** (stratégie de groupe, *Configuration ordinateur > Modèles d'administration > Composants Windows > Services Bureau à distance > Hôte de session Bureau à distance*) :

| Réglage (stratégie) | Valeur | Registre (`HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services`) |
|---|---|---|
| *Limites de temps de session* : définir une limite de temps pour les sessions déconnectées | 1 minute | `MaxDisconnectionTime` = 60000 |
| *Limites de temps de session* : mettre fin à la session quand les limites de temps sont atteintes | activé | `fResetBroken` = 1 |
| *Connexions* : restreindre chaque utilisateur à une seule session | activé | `fSingleSessionPerUser` = 1 |
| *Connexions* : autoriser la gestion à distance des sessions (RPC) | activé | `AllowRemoteRPC` = 1 (`HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server`) |

La plus petite durée proposée par la stratégie est 1 minute : c'est une fenêtre de rattachement que seule la fermeture par l'agent supprime. `AllowRemoteRPC` et l'accès de l'agent au port 445 de la cible (canaux nommés de gestion des sessions) sont nécessaires au mécanisme de la section 4. La signature SMB exigée sur les cibles est recommandée (section « Limites »).

### 6. Codes et événements

| Code | Cas | Événement |
|---|---|---|
| `RDP-E018` | une session du même compte est tenue par une autre connexion : refus | `rdp.session_in_use` |
| `RDP-E019` | sessions du compte impossibles à lister ou à fermer, aucun mécanisme sur l'agent, ou `keep` en production | `rdp.session_cleanup_failed` |
| `AGT-E013` | échec de l'API WTS (`ostena-platform`), repris dans le message de `RDP-E019` | — |
| `CFG-P022` | `rdp.disconnected_sessions = "keep"` en production | `config.weakening` en développement |

Événements de succès et d'avertissement :

- `rdp.session_logged_off` (info) : `target`, `session` (identifiant sur la cible), `state` (état avant fermeture), `moment` (`before` ou `end`) ;
- `rdp.session_cleanup_skipped` (warn, `code = CFG-P022`) : sessions laissées déconnectées en développement.

## Conséquences

- Deux sessions successives sur le même compte cible n'ont plus rien en commun : une session Restricted Admin ne peut plus hériter d'un mot de passe délégué ni des fenêtres d'un autre administrateur. Le test de CI le vérifie sur une vraie cible Windows avec **un seul compte** pour les deux modes (délégation puis Restricted Admin), et vérifie qu'une session laissée déconnectée est fermée avant la connexion suivante ; le contournement « un compte par mode » est retiré.
- Une session ouverte sur le même compte en dehors d'Ostena (console, autre poste) bloque l'accès par le bastion (`RDP-E018`) au lieu d'être reprise. C'est voulu : la reprise déconnecterait cet utilisateur et donnerait sa session à un autre.
- Ce que l'utilisateur laisse ouvert dans sa session est perdu à la fin : il n'y a plus de reprise d'une session interrompue. Une reconnexion après une coupure du navigateur ouvre une session neuve.
- La connexion ajoute une liste des sessions par RPC (quelques allers-retours vers la cible) ; la fermeture d'une session laissée, rare, prend une à quelques secondes.
- **Agent Debian : plus de RDP en production** tant qu'un mécanisme de fermeture n'existe pas pour lui (point à trancher ci-dessous).
- L'agent Windows a besoin d'un flux vers le port 445 des cibles, en plus de 3389.
- Le test sur un seul compte a révélé un défaut du transport, corrigé avec cette décision : les octets clairs de TLS n'étaient vidés qu'après toute une lecture TCP ; au-delà de 16 Kio retenus, la lecture suivante échouait et la boucle prenait l'erreur pour une fin de session par la cible. La rafale graphique qui suit l'ouverture de session fermait ainsi des sessions de la CI par intermittence. Ils sont désormais vidés après chaque lot d'enregistrements (test unitaire du transport).

### Limites connues

- **Authentification de la vue** : ouverte sur une adresse, la connexion RPC ne peut pas obtenir de ticket Kerberos (pas de SPN pour une adresse) et Windows négocie NTLM. Aucun mot de passe n'est transmis à la cible (défi-réponse seulement), mais un relais NTLM reste possible sans signature SMB exigée par la cible. Cela contredit `rdp.ntlm_fallback = false` pour ce seul canal de gestion : point à trancher.
- En CI, la cible est la machine de l'agent (boucle locale) : l'emprunt d'identité et la liste par RPC sont exercés sur `127.0.0.1`, pas au travers d'un réseau ni avec un compte de domaine. Le laboratoire (ADR-0025) doit couvrir une cible distante membre d'un domaine.
- La correspondance entre une session et le compte se fait sur les noms : sans domaine dans le compte, un homonyme d'un autre domaine est traité comme le compte (une fermeture de trop d'une session déconnectée, ou un refus de trop), jamais l'inverse.
- Les sessions ouvertes par un agent arrêté brutalement restent déconnectées jusqu'à la limite de la stratégie de la cible (section 5), ou jusqu'à la connexion suivante sur le compte, qui les ferme.

### Points à trancher (responsable du projet)

1. **Agent Debian** : accepter qu'il n'ouvre pas de session RDP en production, ou financer un client de l'interface de gestion des sessions ([MS-TSTS] sur SMB 2), ou admettre une option distincte qui s'en remet à la stratégie de la cible (fenêtre de rattachement d'au moins 1 minute).
2. **NTLM sur le canal de gestion** (limite ci-dessus) : l'admettre en exigeant la signature SMB des cibles, ou ouvrir la vue par le nom DNS de la cible (Kerberos) après avoir vérifié qu'il se résout en l'adresse épinglée.
