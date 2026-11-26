# ADR-0018 : Gestionnaire de sessions de l'agent et trait `Driver`

- **Statut** : Accepté. Implémenté au jalon M2, PR 1 : crate `ostena-session`, sessions SSH natives tenues par le gestionnaire, scénario `REG-SEC-06`.
- **Date** : 2026-11-26

## Contexte

Au jalon M1, le serveur SSH de l'agent tient lui-même ses sessions : un sémaphore borne les sessions authentifiées, une table des sessions vivantes sert aux révocations, une minuterie coupe à la durée maximale. RDP (PR 7) puis le navigateur (PR 8) ont besoin des mêmes règles. Les recopier dans chaque protocole donnerait des quotas par protocole, alors que la borne qui protège l'agent est celle de l'agent, et des règles qui divergent au fil des corrections.

Contraintes :

- **quotas sans dépassement** : des ouvertures simultanées ne doivent jamais dépasser une borne, y compris sous une rafale (`REG-SEC-06` : 1 000 ouvertures concurrentes au-delà du quota, aucune en trop) ;
- **pas de place perdue** : la place doit être prise avant de solliciter le core, sinon un attaquant authentifié fait émettre des grants qui seront refusés ensuite ; et une révocation arrivée pendant la décision du core ne doit pas être perdue ;
- **identifiant unique** : l'identifiant de session vient du core, qui le signe dans le grant ; deux sessions de même identifiant sur un agent trahiraient un rejeu ou une erreur, et brouilleraient l'audit ;
- **latence** : rien de tout cela ne doit toucher le chemin des données (objectif p99 ≤ 3 ms ajoutées en SSH) ;
- **empreinte** : pas de nouvelle dépendance tierce ; la crate est testable seule, sans base ni API (comme les crates protocolaires).

## Décision

### La crate `ostena-session`

Un **`SessionManager` par agent**, partagé par tous les protocoles. Il dépend de `ostena-scope` (pour `PinnedTarget`), `thiserror` et `tokio` (`watch`, minuteries), tous déjà dans le binaire. Ni base, ni API, ni entrée-sortie.

**Une table, un verrou.** Toutes les places, réservées ou ouvertes, vivent dans une seule table protégée par un `Mutex`, avec les compteurs par utilisateur et par cible et l'ensemble des identifiants ouverts. La vérification des trois quotas et la prise de la place sont une seule étape sous ce verrou : deux ouvertures simultanées ne peuvent pas voir toutes deux la dernière place libre. Le verrou n'est tenu que le temps de quelques opérations de table, jamais pendant une attente ni pendant l'appel d'un observateur. Il ne concerne que l'ouverture et la fin des sessions, pas le relais.

Alternative écartée : des compteurs atomiques indépendants (comparer-échanger par quota). Prendre trois quotas atomiquement demande de défaire les deux premiers quand le troisième refuse, ce qui laisse voir des états intermédiaires (un refus à tort pendant le retour arrière) ; le gain ne se mesure pas à la fréquence des ouvertures.

**Deux temps : réserver, puis ouvrir.**

1. `reserve(claim)` prend une place pour un utilisateur (`subject`), sa session de connexion et une cible (le nom de ressource demandé), dans les quotas de l'agent, de l'utilisateur et de la cible. Refus : `SES-E001`, `SES-E002`, `SES-E003`, ou `SES-E005` pendant l'arrêt.
2. Le core décide. Pendant ce temps, la place est visible des coupures : une révocation la marque.
3. `activate(session_id, durée)` l'ouvre avec l'identifiant donné par le core, refusé s'il est déjà ouvert sur l'agent (`SES-E004`, la place est rendue). Une coupure reçue pendant la réservation est conservée : la session se termine dès son ouverture.

Une place est rendue quand la `Reservation` ou la `Session` est abandonnée (`Drop`), quel que soit le chemin de sortie.

**Fins de session.** `Session::ended()` attend la première de ces causes et la retient : coupure (révocation, arrêt, enregistrement perdu), durée maximale (la plus courte de celle du core et du plafond de l'agent), délai d'inactivité. Le driver déconnecte ensuite et rend la place par `finish(raison)`. La première cause l'emporte.

**Inactivité sans coût sur le relais.** Le relais marque l'activité par un drapeau atomique (`Activity::touch`, une écriture relâchée par paquet), sans lire l'horloge. La session relève le drapeau tous les huitièmes du délai : une session est coupée entre une fois et 1,125 fois le délai après la dernière activité. Ce qui compte comme activité est l'affaire du driver : en SSH, les données de l'utilisateur vers la cible (frappes, flux montant), pas la sortie de la cible ; une session laissée sur un `tail -f` est inactive.

**Coupures.** `cut_where(sélection, raison)` coupe les places, réservées ou ouvertes, désignées par une sélection sur leur protocole, utilisateur, session de connexion, cible ou identifiant. `shutdown()` refuse les nouvelles places et coupe tout ; `drained()` attend qu'il n'en reste aucune.

**Observateurs.** Un `Observer` est prévenu de chaque ouverture, refus et fin (raison, durée), hors du verrou, sur la tâche qui ouvre ou termine la session. C'est le point d'accroche de l'audit et de l'enregistrement pour les protocoles à venir ; le SSH garde ses événements `ssh.*` et son bilan au core (ADR-0010, ADR-0016).

### Le trait `Driver`

Chaque protocole fournit un `Driver` : `connect(&PinnedTarget, Params, délai) -> Connection`. Il ne reçoit **qu'une `PinnedTarget`** à joindre : ses adresses ont passé le contrôle de périmètre (ADR-0005). Le contrôle est ainsi appliqué à tous les drivers par le type, et non par convention. Ce que le driver joue vers la cible (compte, clé ou certificat épinglé, référence du secret) est dans ses propres `Params` ; ses erreurs gardent leurs codes. La connexion obtenue (`DriverConnection`) sait se fermer et dire si la cible l'a fermée. `ostena_ssh::driver::SshDriver` en est la première implémentation ; RDP (PR 7) et le web (PR 8) suivront.

### Le SSH sur le gestionnaire

Le serveur SSH réserve la place après les contrôles du certificat et du nom d'utilisateur, avant de solliciter le core, puis l'ouvre avec l'identifiant de session du core. Le sémaphore des sessions et la table des sessions vivantes disparaissent : révocations, comptage des sessions pour l'état et attente de l'arrêt passent par le gestionnaire. Les refus gardent les codes du serveur, avec la cause du gestionnaire :

| Cas | Code | Événement | Cause |
|---|---|---|---|
| quota de l'agent, de l'utilisateur, de la ressource | `SSH-E019` | `ssh.connection_limited` | `SES-E001`, `SES-E002`, `SES-E003` |
| arrêt en cours | `SSH-E019` | `ssh.connection_limited` | `SES-E005` |
| identifiant de session déjà ouvert | `SSH-E013` | `ssh.access_refused` | `SES-E004` |
| délai d'inactivité atteint | — | `ssh.session_idle`, puis `ssh.session_closed` (raison `inactive`) | — |

Le transcript (ADR-0016) n'a pas de raison « inactivité » : sa trame de fin porte `expired`, une limite de l'agent comme la durée maximale. L'ajouter changerait le format scellé ; ce n'est pas nécessaire pour la démonstration.

### Configuration

Trois clés facultatives dans `[agent.ssh]`, sans valeur par défaut, pour ne rien changer au comportement du jalon M1 : `max_sessions_per_user` et `max_sessions_per_target` (1 à 256), `idle_timeout_secs` (60 à 86 400). `max_sessions` reste la borne de l'agent (64). Hors bornes : `CFG-V015`. Ces clés passeront dans une section commune à tous les protocoles quand RDP arrivera (PR 7).

### Codes

| Code | Signification |
|---|---|
| `SES-E001` | nombre maximal de sessions de l'agent atteint |
| `SES-E002` | nombre maximal de sessions de l'utilisateur atteint |
| `SES-E003` | nombre maximal de sessions vers la cible atteint |
| `SES-E004` | identifiant de session déjà ouvert sur l'agent |
| `SES-E005` | arrêt de l'agent en cours |

## Conséquences

- **Un seul endroit** pour les quotas, les durées et les coupures ; RDP et le navigateur héritent des mêmes règles et de quotas communs à l'agent.
- **`REG-SEC-06`** (`crates/ostena-session/tests/reg_sec_06.rs`) : 1 000 fils lancés ensemble au-delà du quota de l'agent, d'un utilisateur ou d'une cible obtiennent exactement la borne, les autres le code du quota ; un même identifiant ouvert par 64 fils ne l'est qu'une fois ; sous un va-et-vient de sessions, la borne n'est jamais dépassée. Des tests de propriétés comparent le gestionnaire à un modèle sur des suites d'opérations quelconques (réservation, ouverture, fin, coupure).
- **Latence et empreinte** : le relais ajoute une écriture atomique relâchée par paquet montant ; l'ouverture et la fin d'une session prennent un verrou brièvement. Aucune dépendance tierce nouvelle. Mesures de la PR : banc `cargo xtask bench-ssh` et empreinte au repos inchangés au bruit près (chiffres dans la PR).
- **Comportement SSH inchangé par défaut** : sans les nouvelles clés, seule la borne de 64 sessions s'applique, comme au jalon M1. Un délai d'inactivité par défaut, ou des quotas par utilisateur par défaut, seraient plus sûrs ; c'est une décision du responsable du projet, à prendre avec la section commune de configuration.
- **Révocations par protocole** : `SshServer::revoke_login` ne coupe que les sessions SSH, comme avant. Quand plusieurs protocoles partageront le gestionnaire, la révocation d'une session de connexion se fera au niveau de l'agent (`cut_where` sur la session de connexion, tous protocoles).
- **Le verrou unique** devient un point de contention si l'agent ouvre des milliers de sessions par seconde ; ce n'est pas le profil d'un bastion, et la table pourra être découpée sans changer l'interface.
- **Interdiction outillée** : `deny.toml` réserve `sqlx` à `ostena-core`, si bien qu'une dépendance à la base depuis `ostena-session` ou une crate protocolaire est refusée par `cargo deny`.
