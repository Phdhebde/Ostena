# ADR-0008 : Tunnel entre l'agent et le core, et enrôlement

- **Statut** : Accepté en partie. Le transport, TLS, le multiplexage, les bornes, le heartbeat, les messages de contrôle et la PKI à deux niveaux sont décidés et implémentés (PR 1, 2 et 3a du lot L2, partie 2). La protection au repos de la clé de la CA est décidée et sera implémentée avec le core. L'enrôlement, le renouvellement et la révocation sont implémentés (lot L2, PR 3b). La reconnexion (backoff borné avec gigue complète, état dans `ostena agent status`) est implémentée (lot L2). Le repli TLS 1.3 sur TCP, avec son multiplexeur et le mode `auto`, est implémenté (jalon M2, PR 2a et 2b). La grâce qui garde les sessions SSH pendant une coupure courte viendra à la PR 2c. Les messages de l'accès SSH natif sont implémentés côté agent et dans le core de test (jalon M1, PR 4) ; leur traitement par le core viendra à la PR 5 du jalon M1.
- **Date** : 2026-11-11
- **Révision** : 2026-11-15, messages de l'accès SSH natif et `TUN-E030` (jalon M1, PR 4)
- **Révision** : 2026-11-25, autorités d'hôtes dans `ssh_trust`, liaison du grant exigée par l'agent (jalon M1, PR 5a)
- **Révision** : 2026-11-25, classe de flux `enregistrement` pour les transcripts, quatre flux par session (jalon M1, PR 8, ADR-0016)
- **Révision** : 2026-11-26, repli TLS 1.3 sur TCP : multiplexeur, écoute TCP du core, mode `auto` et `tunnel.fallback` (jalon M2, PR 2a et 2b)

## Contexte

L'agent passerelle doit joindre le core sans que le core puisse l'appeler. Le pare-feu n'ouvre que le sens agent → core (*dial-back*). Le tunnel porte :
- le plan de contrôle : paramètres de session, politique de périmètre, clés de grant ;
- le trafic des sessions, avec une latence ajoutée minimale et la priorité aux entrées clavier et souris.

Il doit résister aux coupures et rester borné en mémoire. Les algorithmes sont figés (ADR-0009).

## Décision

### Transport : QUIC, avec un repli TLS 1.3 sur TCP

**QUIC (`quinn` 0.11)** est le transport principal :
- des flux indépendants, donc une perte ne bloque que son flux ;
- des priorités d'envoi par flux ;
- un contrôle de flux natif.

**Le repli** (jalon M2, PR 2a et 2b) passe par TLS 1.3 sur TCP avec un **multiplexeur maison minimal** (`ostena_tunnel::mux`), et non par HTTP/2 :
- le mTLS va de bout en bout, donc HTTP/2 n'apporte rien pour traverser un pare-feu ou un proxy ;
- son ordonnanceur interne empêcherait la priorité stricte des entrées.

**Choix du transport** (`[agent] transport`) :
- `auto` (par défaut) : l'agent tente QUIC et lance TCP en parallèle s'il n'a pas de réponse en 1 s (`FALLBACK_AFTER`), ou aussitôt si QUIC échoue sur le chemin (connexion perdue, erreur locale, poignée de main interrompue). Le premier tunnel établi gagne, l'autre tentative est abandonnée. Un refus du pair (certificat, groupe, suite, ALPN) n'est pas retenté sur TCP : il y serait le même ;
- `quic` ou `tcp` : un seul transport ;
- le repli est journalisé (`tunnel.fallback`, avertissement) à chaque connexion qui l'utilise : QUIC est retenté à chaque reconnexion ;
- `ostena agent status` affiche le transport en cours (« connecté (TCP) »).

C'est une rétrogradation de performance, pas de sécurité : la configuration TLS est la même (`ostena-crypto::tls`, `SecP256r1MLKEM768` seul, `TLS_AES_256_GCM_SHA384` seule), l'ALPN aussi (`ostena-tunnel/1`). Le core écoute en TCP **sur le même port** que QUIC (8443 par défaut) : l'agent n'a qu'une adresse du core. Le core mène au plus 32 poignées de main TCP à la fois ; au-delà, les connexions attendent.

**Le multiplexeur** reprend le modèle de QUIC, en plus simple :
- **trames** : un en-tête de 8 octets (type, drapeaux nuls, longueur sur 16 bits, flux sur 32 bits), puis 16 Kio de données au plus. Douze types : `SETTINGS`, `OPEN`, `DATA`, `FIN`, `RESET`, `STOP`, `CREDIT`, `FIN_ACK`, `MAX_STREAMS`, `PING`, `PONG`, `CLOSE` ;
- **mêmes flux** : le flux de contrôle d'abord, ouvert par l'agent, puis jusqu'à quatre flux par session avec leur en-tête de 18 octets. L'agent ouvre les flux impairs, le core les pairs, chacun le suivant de son côté ;
- **priorités strictes** : l'écrivain sert toujours la priorité la plus haute qui a quelque chose à envoyer (mêmes valeurs qu'en QUIC), à tour de rôle entre égaux, une trame de 16 Kio au plus à la fois. Une frappe attend donc au plus une trame de transfert, plus le lot en cours d'écriture (32 Kio) ;
- **contrôle de flux de bout en bout** : fenêtres par flux et par connexion, celles de `Limits` (256 Kio et 8 Mio). Un écrivain ne met en file que le crédit accordé par le pair, qui ne le renouvelle (`CREDIT`) qu'une fois les octets lus par l'application. Les tampons restent donc bornés comme en QUIC, et la contre-pression remonte jusqu'à la fenêtre TCP de la cible ;
- **limite de flux** : chaque côté annonce dans `SETTINGS` le nombre de flux que le pair peut ouvrir (`Limits::max_streams`), puis le relève (`MAX_STREAMS`) à chaque flux fermé des deux côtés. Un flux de plus attend ;
- **bornes et vivacité** : `PING` toutes les 5 s (`keep_alive`), connexion déclarée perdue après 15 s sans trame (`TUN-E013`), en plus du heartbeat applicatif ;
- **fermeture** : `CLOSE` porte le code et le message de l'erreur (200 octets au plus), comme la trame de fermeture de QUIC : l'agent reçoit le code du core (`TUN-E005` à la révocation, par exemple) ;
- **arrêt et réinitialisation** : `STOP` et `RESET` portent un code applicatif, `FIN_ACK` dit que le pair a reçu toutes les données et la fin (l'équivalent de l'accusé QUIC qu'attend le flux d'enregistrement, ADR-0016).

**Toute trame reçue est une entrée non fiable.** Le décodeur vérifie l'en-tête (type connu, drapeaux nuls, longueur permise pour le type, flux nul ou non selon le type) avant d'attendre la charge : une longueur forgée ne fait jamais tamponner plus d'une trame. L'état refuse ensuite toute violation (`TUN-E010`, la connexion est fermée avec ce code) : première trame autre que `SETTINGS`, paramètres hors des bornes de `Limits`, ouverture hors séquence ou au-delà de la limite, données sur un flux jamais ouvert ou après sa fin, dépassement d'une fenêtre, crédit nul, limite de flux en baisse, `FIN_ACK` d'une fin non envoyée. Une autre version donne `TUN-E011`. Des trames tardives pour un flux déjà oublié sont ignorées (leurs données rendent leur crédit à la connexion). Cible `cargo-fuzz` : `tunnel_mux_decode` (décodeur et état, avec un corpus rejoué par les tests).

**Codes sur TCP.** En QUIC, la raison d'un refus TLS voyage dans la trame de fermeture ; sur TCP, seule l'alerte TLS arrive au pair. Les codes restent les mêmes des deux côtés, sauf trois cas :

| Refus | Côté qui le détecte | Ce que voit l'autre côté sur TCP |
|---|---|---|
| groupe `SecP256r1MLKEM768` absent (`TUN-E001`) | core | `TUN-E002` (alerte `handshake_failure`) |
| registre du core illisible (`TUN-E029`) | core | `TUN-E016` (alerte `bad_certificate`) |
| certificat du core non émis par la racine (`TUN-E017`) | agent | `TUN-E016` |

Le côté qui détecte le refus journalise toujours le code exact.

**QUIC Initial.** QUIC protège ses paquets *Initial* avec AES-128-GCM et des clés dérivées d'un sel public et de l'identifiant de connexion (RFC 9001 § 5.2).
- Cela ne cache rien à un observateur : ces paquets ne portent que le début de la poignée de main.
- La poignée de main elle-même et toutes les données utilisent `TLS_AES_256_GCM_SHA384`.
- AES-128 n'est pas proposé à la négociation (`ostena_crypto::tls::quic_initial_suite`).

### TLS

Paramètres (ADR-0009, construits par `ostena-crypto::tls` uniquement) :
- TLS 1.3 seul ;
- `TLS_AES_256_GCM_SHA384` seule et `SecP256r1MLKEM768` seul ;
- signatures ECDSA P-256 / SHA-256 seules ;
- pas de reprise de session ni de 0-RTT ;
- ALPN `ostena-tunnel/1`, vérifié après la poignée de main.

**Côté agent :**
- la **racine hors ligne** est épinglée (`agent.tls_core_ca`) ;
- le certificat du core doit être **signé directement par la racine**, avec l'EKU serverAuth et le nom de `agent.core_address` (nom DNS ou adresse IP) ;
- un core qui présente une chaîne (par exemple un certificat signé par la CA émettrice en ligne, avec son intermédiaire) est refusé avant tout autre contrôle (`TUN-E017`) ; sans son intermédiaire, ce certificat ne remonte pas à la racine (`TUN-E003`).

**Côté core :**
- le certificat client est **obligatoire au niveau TLS** ;
- il est vérifié contre la ou les CA émettrices (deux pendant une rotation), puis contre le **registre** à chaque poignée de main : un agent inconnu donne `TUN-E006`, un agent révoqué `TUN-E005`. Le registre identifie un agent par le SHA-256 de son certificat ;
- `quinn` transmet la raison du refus dans la trame de fermeture : l'agent obtient le même code que le core.

### Multiplexage, priorités, bornes

- **Flux de contrôle** : le premier flux bidirectionnel, ouvert par l'agent, de priorité 40.
- **Flux de session** : jusqu'à quatre par session, un par classe, ouverts à la demande, chacun précédé d'un en-tête de 18 octets (version, classe, UUID de session).

| Classe | Contenu | Priorité QUIC |
|---|---|---|
| interactif | entrées, terminal SSH | 30 |
| affichage | graphismes RDP et VNC | 20 |
| transfert | fichiers, gros presse-papiers | 10 |
| enregistrement | transcript de la session, de l'agent vers le core (ADR-0016) | 25 |

Le flux d'enregistrement passe avant l'affichage et le transfert : une sortie n'est relayée à l'utilisateur qu'une fois remise à l'enregistreur, et ce flux ne doit pas la retarder. Il reste derrière l'interactif. Le core arrête un flux d'enregistrement qu'il refuse (code applicatif 1, `REC-E002`) et, au jalon M1, tout flux de session d'une autre classe (`tunnel.channel_refused`) : il ne relaie pas encore de données de session.

**Bornes par défaut** (`Limits`, validées au démarrage) :
- 256 sessions, soit 1025 flux au plus (quatre par session et le flux de contrôle). La limite est **appliquée par QUIC lui-même** : un flux de plus attend du crédit ;
- fenêtre de 256 Kio par flux et de 8 Mio par connexion, soit **16 Mio de tampons au plus par tunnel**, alloués à la demande ;
- pas de flux unidirectionnel ni de datagramme.

**Contrôle de flux de bout en bout** : l'agent ne lit le socket de la cible que si son flux a du crédit. La contre-pression remonte donc jusqu'à la fenêtre TCP de la cible.

### Robustesse

- **Détection de coupure** :
  - keep-alive QUIC toutes les 5 s, délai d'inactivité de 15 s (`TUN-E013`) ;
  - **heartbeat applicatif** sur le flux de contrôle : Ping toutes les 10 s au plus (l'intervalle est annoncé par le core dans `HelloAck`), et pair déclaré muet sans Pong pendant 30 s (`TUN-E012`). Il détecte un core dont QUIC répond mais dont l'application est bloquée.
- **Reconnexion** (`ostena_tunnel::link::AgentLink`, démarré avec l'agent, quel que soit le transport) :
  - backoff exponentiel de 1 s à 60 s, avec une **gigue complète** : un délai tiré au hasard entre zéro et la borne, pour que des agents coupés ensemble ne reviennent pas ensemble ;
  - la séquence repart de zéro après une connexion restée stable 60 s ;
  - l'adresse du core est résolue à chaque tentative ;
  - la clé et le certificat sont **relus à chaque connexion**, si bien qu'un certificat renouvelé sert dès la suivante ;
  - l'état est partagé avec le plan de contrôle : `ostena agent status` affiche « connecté (QUIC) depuis N s, RTT … » (ou « (TCP) » ; sur TCP, le RTT est mesuré par les `PING` du multiplexeur) ou « non connecté, nouvelle tentative dans N s (code : cause) », et l'échéance du certificat.
- **Démarrage** : les noms des composants Ostena sont résolus **avant** le lien. En production, un nom introuvable refuse le démarrage (`CFG-P010`). Les noms sont résolus de nouveau toutes les 5 minutes ; un échec garde les adresses précédentes, et l'union garde les anciennes adresses une période de plus. Sans `tls_core_ca` (développement), le lien n'est pas démarré et `status` le dit.
- **État de l'agent** : la clé, le certificat et le journal anti-rejeu sont sur disque. La politique et le jeu de clés sont repoussés par le core à chaque connexion. Les sessions en cours sont fermées à la coupure (v1).

### Messages de contrôle v1

- **Format** : JSON strict (`deny_unknown_fields`), préfixé par sa longueur sur 4 octets.
- **Tailles** : 64 Kio au plus par message, 1 Mio pour une politique. La longueur est vérifiée avant toute allocation.

| Sens | Messages |
|---|---|
| agent → core | `hello`, `ping`, `pong`, `session_request`, `session_closed`, `renew`, `ssh_host_key`, `ssh_grant_request` |
| core → agent | `hello_ack`, `ping`, `pong`, `policy`, `key_set`, `session_params`, `session_refused`, `certificate`, `shutdown`, `ssh_trust`, `ssh_grant`, `login_revoked` |

Les messages `ssh_*` et `login_revoked` sont décrits plus bas (« Accès SSH natif »).

**Tout message reçu est une entrée non fiable.** Toute valeur invalide ferme le tunnel (`TUN-E010`), et une autre version de protocole donne `TUN-E011`.

| Contrôle | Règle |
|---|---|
| Textes | bornés, sans caractère de contrôle (ils finissent dans les journaux) |
| Identifiants | UUID canoniques |
| Grant | forme texte valide |
| Jeu de clés | 16 clés au plus, `kid` cohérent avec la clé, pas de `kid` en double, clé sur la courbe |
| Politique | compilée comme en production : aucune exception au plancher, aucun affaiblissement non justifié |
| Hôte de session | syntaxe vérifiée, puis de nouveau contrôlé par `ostena-scope` avant la connexion |

**La configuration locale est un plafond** (`ostena_tunnel::gateway`). La politique effective est l'intersection de la politique locale (`[agent.scope]`) et de celle du core, plus le plancher d'infrastructure. **Si la politique locale est vide, rien ne passe, quoi que pousse le core.** Un core compromis ne peut pas élargir le périmètre d'une passerelle.

**Ce que le core pousse** :
- **Politique** (`policy`) : elle doit nommer le groupe de l'agent (`TUN-E028` sinon), et doit se compiler en production sur l'agent (`TUN-E028`). Une cible passe seulement si la politique locale et celle du core l'autorisent toutes les deux ; les composants Ostena résolus par l'agent (`CFG-P010`) sont ajoutés aux deux. **Tant que le core n'a pas poussé de politique, rien ne passe** (`TUN-E026`). Une version inférieure à celle appliquée est refusée (`TUN-E025`) ; la même version est ignorée. Un refus laisse la politique précédente en place.
- **Clés de grant** (`key_set`) : le jeu poussé remplace le précédent ; une clé absente est retirée. **Sa version ne revient jamais en arrière** (`TUN-E024`), même après un redémarrage de l'agent : la dernière version acceptée est écrite dans `keyset.version`, à côté du journal anti-rejeu, **avant** d'être utilisée. Le fichier est créé avec ses droits définitifs (0600, ou une ACL protégée réservée au compte de l'agent), synchronisé, puis renommé sur l'ancien (écriture atomique). S'il ne peut pas être écrit, le jeu est refusé. S'il existe mais est illisible, l'agent refuse de démarrer (`TUN-E015`) : la protection ne pourrait plus être garantie. La reprise est explicite : `ostena agent keyset-state repair`, agent arrêté et après confirmation, conserve l'original (`.corrupt-<horodatage>`), journalise `keyset_state.repaired` et réinitialise l'état. L'agent accepte alors la version poussée à la connexion suivante (`agent.keyset_applied` avec `initial`), puis aucune inférieure : c'est la seule fenêtre où le retour en arrière n'est pas empêché, d'où la confirmation et la consigne de relever d'abord la version sur le core. Après un redémarrage, l'agent n'a pas de clés tant que le core n'a pas renvoyé une version au moins égale.

**Ouverture d'une session** (`Gateway::open_session`) :
1. pas de politique ni de clés poussées : refus (`TUN-E026`) ;
2. l'agent vérifie le grant avec les clés poussées et **consomme son jti dans son propre journal** (`GRT-E…`) ;
3. il envoie `session_request` ; le core vérifie de nouveau le grant et **consomme le jti dans son propre registre** : un grant rejoué sur une autre passerelle du même groupe est refusé par le core (`session_refused`, `GRT-E010`) ;
4. sans réponse sous 5 s : `TUN-E027` ;
5. la réponse `session_params` doit correspondre au grant (protocole, durée au plus celle du grant), sinon `TUN-E010` ;
6. l'hôte répondu est résolu une fois et épinglé par le contrôle de périmètre local, puis chaque adresse est vérifiée par la politique du core (`SCP-E…`).

Événements : `agent.policy_applied`, `agent.policy_refused` (code), `agent.keyset_applied`, `agent.keyset_refused` (code), `agent.session_granted`, `agent.session_refused` (code du core), `agent.session_answer_unexpected` ; reprise de l'état : `keyset_state.repaired`, `keyset_state.repair_failed`.

### Accès SSH natif (décidé le 2026-11-15, jalon M1, PR 4)

Le parcours est celui de l'ADR-0010 ; le tunnel porte cinq messages de plus. Aucun nom de champ ne contient `key` : la règle de masquage des journaux (`ostena_common::logging`) les effacerait.

| Message | Sens | Contenu | Contrôles (sinon `TUN-E010`) |
|---|---|---|---|
| `ssh_host_key` | agent → core | `p256_public` (point SEC1 non compressé, base64url), `proof` | point sur la courbe ; `proof` signature de 64 octets |
| `ssh_grant_request` | agent → core | `request_id`, `subject`, `login_session`, `certificate_sha256`, `account`, `resource`, `client_address` | UUID canoniques, 64 hexadécimaux minuscules, compte de 1 à 256 octets sans caractère de contrôle ni espace aux bords, ressource `[a-z0-9][a-z0-9.-]{0,62}`, `ip:port` |
| `ssh_trust` | core → agent | `version`, `user_ca_p256_public` (1 à 4), `host_ca_p256_public` (1 à 4, requis), `host_certificate` facultatif | version non nulle, autorités de chaque sorte sur la courbe et distinctes, certificat d'hôte du type figé d'au plus 4096 octets |
| `ssh_grant` | core → agent | `request_id`, `grant` | forme texte du grant |
| `login_revoked` | core → agent | `login_session` | UUID canonique |

`session_params` gagne `account` et `target_p256_public` (clé hôte épinglée de la cible) : **tous deux requis quand le protocole est SSH**, refusés pour les autres protocoles (`TUN-E010`).

**Preuve de possession de la clé d'hôte.** Sur le modèle de `renew` : signature par la clé d'hôte SSH de l'agent de `"ostena-ssh-host-key-v1\0"` ‖ SHA-256 du certificat du tunnel courant ‖ la clé (`ostena_tunnel::ssh`). Le core la vérifie (`TUN-E022`) avant de certifier la clé et de renvoyer le certificat d'hôte dans `ssh_trust`.

**Confiance SSH** (`GatewayState::apply_ssh_trust`) : la version ne recule pas (`TUN-E030`, la confiance précédente reste) ; la même poussée répétée est ignorée, mais la même version avec un autre contenu est refusée (`TUN-E030`). Elle est publiée au serveur SSH de l'agent, qui vérifie le certificat d'hôte avant de s'en servir, **y compris sa signature par l'une des autorités d'hôtes poussées** (`SSH-E018`, ADR-0010). Les autorités sont des listes pour permettre une rotation.

**Ouverture d'une session SSH** (`Gateway::open_ssh_session`) :
1. pas de politique, de clés ou de confiance SSH poussées : refus (`TUN-E026`) ;
2. l'agent envoie `ssh_grant_request` ; sans réponse sous 5 s : `TUN-E027` ; un refus du core revient en `session_refused` avec son code ;
3. l'agent vérifie le grant et consomme son jti dans son journal, puis exige le sujet du certificat, le protocole SSH et la **liaison** à la session de connexion et au compte demandés (format v2, ADR-0004) (`TUN-E010`) : un grant qui ne correspond pas est donc brûlé ;
4. le chemin commun suit : `session_request`, jti consommé par le core, `session_params` ;
5. la réponse doit porter le compte demandé et la clé hôte de la cible (`TUN-E010`), puis la cible est épinglée par le contrôle de périmètre.

`login_revoked` est diffusé au serveur SSH, qui coupe les sessions de cette session de connexion.

Événements : `agent.ssh_trust_applied`, `agent.ssh_trust_refused` (code), `agent.login_revoked`.

Le core de test (`ostena_tunnel::testing`) répond à `ssh_grant_request` depuis un inventaire de ressources nommées (avec des réglages pour mal se comporter : autre sujet, autre protocole, autre compte, liaison à un autre compte, clé hôte absente), enregistre les clés d'hôte reçues et pousse la confiance de ses propres autorités d'utilisateurs et d'hôtes. Le core réel les traite depuis la PR 5b du jalon M1 (ADR-0014) : décision depuis son inventaire, certificat d'hôte, poussées de la confiance SSH et diffusion de `login_revoked`, y compris à la reconnexion d'un agent pour les sessions de connexion révoquées et pas encore expirées pour lesquelles il a reçu un grant.

### Enrôlement, renouvellement, révocation

**Le jeton** (`EnrollmentService::issue_token`) :
- émis par le core pour un groupe de passerelles ;
- un identifiant de 128 bits et un secret de 256 bits ; le core ne garde que le SHA-256 du secret, comparé en temps constant ;
- valide 15 min par défaut, 1 h au plus ;
- forme texte `ostena-enroll-v1.<id>.<secret>` (base64url), remise à l'agent par fichier ou par l'entrée standard, jamais en argument.

**L'écouteur d'enrôlement** :
- port distinct (`agent.enrollment_address`, par défaut l'hôte du core sur le port 8444), en TLS 1.3 avec le certificat serveur signé par la racine, sans certificat client ;
- **fermé par défaut** : il est lié quand un jeton est émis, et fermé dès qu'il ne reste aucun jeton valide (tous utilisés ou expirés ; une tâche surveille l'échéance la plus proche) ;
- il ne sert **que** le protocole d'enrôlement :
  - un autre ALPN échoue à la poignée de main TLS (`TUN-E008`) ;
  - tout message autre qu'une demande bien formée reçoit `refused` avec `TUN-E010`.

Ces trois comportements sont testés.

**Le protocole**, sur un flux ouvert par le core (JSON strict, 16 Kio au plus) :
1. le core envoie `challenge` : 32 octets aléatoires ;
2. l'agent, qui a généré sa clé ECDSA P-256 et l'a déjà écrite sur disque (fichier en `0600`), envoie `request` : identifiant et secret du jeton (protégés par TLS), groupe de sa configuration, clé publique, et une **preuve de possession**. Celle-ci est une signature de la nouvelle clé sur : un préfixe de domaine, le défi, l'identifiant du jeton, le groupe, la clé publique, et le SHA-256 du certificat du core vu par l'agent (liaison au canal) ;
3. le core vérifie tout, dans cet ordre, et **sous un même verrou** :

   | Contrôle | Refus |
   |---|---|
   | jeton connu et secret exact | `TUN-E018` |
   | jeton non utilisé | `TUN-E020` |
   | jeton non expiré | `TUN-E019` |
   | groupe du jeton égal à celui de la demande | `TUN-E021` |
   | preuve de possession valide | `TUN-E022` |

   Puis il **consomme le jeton avant d'émettre**.

   Une erreur de groupe ne consomme pas le jeton : c'est une erreur de configuration de l'agent, que l'opérateur corrige avant de recommencer. En revanche :
   - **chaque échec sur un jeton connu compte, quel qu'en soit le motif** (secret faux, expiré, autre groupe, preuve invalide). Au **troisième**, le jeton est **brûlé** définitivement (`TUN-E023`), même pour le bon groupe ;
   - un jeton présenté pour un autre groupe, une preuve de possession invalide ou un jeton brûlé émettent l'événement de sécurité **`tunnel.enrollment_suspicious`** : adresse de l'appelant, groupe demandé, identifiant du jeton, nombre d'échecs et code. **Jamais le secret.**
4. le core répond `accepted` : le certificat (30 jours, SAN `urn:ostena:gateway-group:<uuid>` et `urn:ostena:agent:<uuid>`), l'identifiant de l'agent et la validité. L'agent vérifie que le certificat porte bien sa clé publique.

Pas de PKCS#10, donc aucun analyseur ASN.1 exposé côté core.

**`ostena agent enroll --config … --token-file <fichier|->`** :
- lit la configuration sans exiger la clé ni le certificat ;
- refuse si l'un d'eux existe déjà ;
- écrit la clé avant tout échange. Si l'enrôlement échoue, la clé reste : une **clé sans certificat** est réutilisée à la tentative suivante (ou recréée si elle est illisible), si bien qu'une nouvelle tentative n'est jamais bloquée. Une clé accompagnée d'un certificat n'est jamais écrasée ;
- écrit ensuite le certificat.

**Le renouvellement**, aux 2/3 de la validité, par le tunnel :
- l'agent génère une **nouvelle clé** et envoie `renew` : la clé publique et une signature de cette clé sur un préfixe de domaine, le SHA-256 du certificat du tunnel courant et la clé publique ;
- le core vérifie la preuve (`TUN-E022`), émet un certificat pour le même agent et le même groupe, l'enregistre, et répond `certificate` avec la validité. L'agent planifie ainsi le renouvellement suivant sans analyser de X.509 ;
- l'ancien certificat reste valide jusqu'à son expiration, sauf révocation.

**Côté agent, le renouvellement est automatique** :
- l'agent lit la validité de son certificat (lecture DER minimale, `pki::certificate_validity`) et arme une échéance aux 2/3 ;
- à l'échéance, il envoie `renew` avec une nouvelle clé ;
- à la réception de `certificate`, il vérifie que le certificat porte bien sa nouvelle clé ;
- il crée `agent.key.new` **avec ses droits définitifs avant d'y écrire quoi que ce soit** (`ostena-platform::private_file`) : mode `0600` passé à la création sous Linux ; sous Windows, un descripteur de sécurité protégé (sans héritage) passé à `CreateFileW` : SYSTEM et Administrateurs en contrôle total, le compte de l'agent en lecture et suppression ;
- il écrit `agent.crt.new`, puis renomme la clé, puis le certificat. Le renommage remplace l'ancienne clé, qui disparaît du disque ;
- dès qu'aucun canal de session n'est ouvert, il ferme la connexion et se reconnecte aussitôt avec la nouvelle identité, sans délai d'attente. Une session en cours n'est jamais coupée pour cela.

**L'ancienne clé en mémoire.** La clé lue sur disque n'est gardée que le temps de construire la configuration TLS (`SecretBytes`, effacé à la libération). Elle ne vit ensuite que dans l'état TLS de la connexion en cours (aws-lc efface les clés qu'il libère). La reconnexion qui suit le renouvellement la libère : sans session ouverte, c'est immédiat ; avec des sessions ouvertes, c'est à la fermeture de la dernière.

**L'identité vit dans le dossier d'état** (`/var/lib/ostena`, `C:ProgramDataOstenastate`) : c'est le seul dossier où le service peut écrire (`ProtectSystem=strict` sous Linux ; lecture seule sur le dossier de configuration sous Windows). `ostena agent install` donne au service, sous Windows, la lecture et la suppression sur la clé (`(R,D)`), pour qu'un renouvellement puisse la remplacer. Au démarrage, si le dossier de la clé ou du certificat n'est pas inscriptible, l'agent le signale aussitôt (`agent.renewal_impossible`), plutôt qu'au renouvellement, vingt jours plus tard.

**Renouvellement en retard.** Une surveillance, indépendante de la connexion, relit la validité du certificat sur disque toutes les heures. À partir de **90 %** de la validité sans renouvellement réussi :
- `ostena agent status` affiche un avertissement ;
- l'agent émet `tunnel.renewal_overdue` (échéance, secondes restantes), **répété chaque heure** jusqu'au renouvellement.

L'horloge est injectable (`link::Clock`) : les tests qui dépendent du temps utilisent une horloge simulée et le temps suspendu de Tokio, sans marge de tolérance.

**Renouvellement interrompu** par un arrêt de l'agent, traité à la connexion suivante, avant de lire l'identité :
- `agent.key.new` encore présent : les renommages n'avaient pas commencé, la paire courante est cohérente ; les fichiers `.new` sont supprimés et le renouvellement sera redemandé ;
- seul `agent.crt.new` reste : la clé a été renommée ; le certificat l'est à son tour.

**La révocation** :
- c'est un statut dans le registre, contrôlé à chaque poignée de main (`TUN-E005`) ;
- le core **ferme aussitôt les tunnels ouverts** sous ce certificat, avec le code `TUN-E005`, que l'agent reçoit tel quel.

**Événements** :
- côté core : `enroll.token_issued`, `enroll.listener_opened`, `enroll.listener_closed`, `enroll.accepted` (agent, groupe, empreinte), `enroll.refused` (code), `tunnel.enrollment_suspicious` (sécurité) ;
- côté agent : `agent.enrolled`.

### Clé de la CA du core (décidé le 2026-11-11)

**1. Hiérarchie à deux niveaux, rôles séparés :**

| | Racine hors ligne | CA émettrice en ligne |
|---|---|---|
| Algorithme, durée | ECDSA P-256, 10 ans | ECDSA P-256, 1 an |
| Où vit la clé | hors ligne : deux copies scellées sur deux supports, puis HSM | sur le core |
| Ce qu'elle signe | la CA émettrice et le **certificat serveur du core** (1 an), lors d'une cérémonie | **uniquement les certificats d'agent** |
| Contraintes | `pathLen 1` | `pathLen 0`, EKU clientAuth seul, contraintes de nom excluant **tous les noms DNS et toutes les adresses IP** |
| Qui lui fait confiance | les agents (ils l'épinglent) | le core, pour les certificats clients |

**Écart à la demande initiale.** Une contrainte de nom X.509 restreignant les SAN à `urn:ostena:agent` et `urn:ostena:gateway-group` est impossible :
- RFC 5280 § 4.2.1.10 : les contraintes d'URI ne portent que sur la partie hôte, et une URI sans hôte (c'est le cas d'un URN) doit faire **rejeter** le certificat ;
- webpki ne gère pas ce type de contrainte.

La restriction est donc assurée autrement :
- les contraintes d'exclusion DNS et IP empêchent la CA émettrice de produire un certificat serveur valide pour quiconque (testé) ;
- le code d'émission (`IssuingAuthority::issue_agent`) n'accepte que des identifiants en minuscules, chiffres et tirets ;
- le registre du core n'accepte que les certificats qu'il a émis.

**Conséquence : la compromission de la CA émettrice ne permet que de fabriquer des certificats d'agent**, et ceux-ci sont refusés par le registre (empreinte inconnue, `TUN-E006`). Elle ne permet pas d'usurper le core auprès des agents : ils n'acceptent qu'un certificat signé directement par la racine (`TUN-E017`).

**2. Stockage sur le core** (Linux) :
- clé PKCS#8 dans `/var/lib/ostena/ca/issuing.key` ;
- dossier en `0700` et fichier en `0600`, propriété du compte du service du core ;
- certificat dans `/etc/ostena/ca/issuing.pem` ;
- certificat serveur et sa clé à côté (`server.pem`, `server.key`), avec les mêmes droits et la même protection au repos.

**3. Protection au repos, liée au TPM 2.0, en attendant le HSM** :
- la clé n'est **jamais en clair sur disque** : elle est chiffrée avec `systemd-creds encrypt --with-key=tpm2` (ou `host+tpm2`) et chargée par l'unité du core avec `LoadCredentialEncrypted=` ;
- systemd la déchiffre au démarrage dans `$CREDENTIALS_DIRECTORY` (ramfs non swappé, lisible par le seul service) ; le core la lit dans un `Secret` ;
- **en production, un chiffrement sans TPM 2.0 est refusé** : le core ne démarre pas, sauf dérogation explicite.

  Sur le modèle de `allow_short_names`, la dérogation exige :
  - une justification d'au moins 20 caractères ;
  - une date d'échéance d'au plus un an ;
  - une journalisation à chaque démarrage.

  Passé l'échéance, le refus revient.

**4. Règles de production** (implémentées avec le lot du core, qui n'a pas encore de configuration) :
- **`CFG-P011`** : clé d'une CA ou du serveur lisible au-delà du compte du service, ou dossier modifiable par un autre compte ;
- **`CFG-P012`** : clé d'une CA ou du serveur chargée en clair depuis un fichier, au lieu d'un credential systemd chiffré ou, plus tard, d'un HSM ;
- **`CFG-P013`** : credential non lié au TPM 2.0 sans dérogation valide (justification d'au moins 20 caractères, échéance d'au plus un an).

En développement, les trois sont journalisées et acceptées.

**5. Cérémonie** (`ostena ca`, procédure dans `docs/exploitation/ceremonie-racine.md`) :
- **Sur le poste isolé**, `ostena ca root init --name … --out <support A> --out <support B>` :
  - tire la clé racine et un **secret de 256 bits**, qui scelle la clé (voir l'ADR-0009). La racine vit 10 ans, donc au-delà de 2030 : 256 bits respectent la recommandation post-quantique de PG-083 v3.00 (`RecoPQTailleCléSym`, § 2.1.1 : au moins 192 bits) et s'alignent sur AES-256 ;
  - partage ce secret en **trois parts dont deux quelconques suffisent** (partage de Shamir 2 sur 3), une par dépositaire : la perte d'une enveloppe ne rend pas la racine irrécupérable, et aucun dépositaire seul ne peut la rouvrir ;
  - affiche les parts une seule fois, chacune en 56 caractères base32 (identifiant, 32 octets de valeur, CRC-16) ; la CRC-16 détecte toute faute sur un caractère ;
  - écrit sur chaque support `root.pem`, `root.name` et `root.key.sealed`.
- **Sur le core**, `ostena ca key new` génère chaque clé (CA émettrice, serveur). Seule la clé publique est portée à la cérémonie.
- **À la cérémonie**, `ostena ca issuing sign` et `ostena ca server sign` certifient ces clés publiques avec la racine. Deux parts sont lues sur l'entrée standard.
- **Enveloppe perdue ou changement de dépositaire** : `ostena ca root reseal` rouvre la racine avec deux parts et la scelle sous un nouveau secret, en trois nouvelles parts, sur des supports neufs. Les anciens supports et enveloppes sont ensuite détruits.
- Rien n'est jamais écrasé.

**Implémentation du partage : `vsss-rs`** (Apache-2.0 ou MIT), utilisé dans `ostena-crypto` seulement.
- Ses auteurs indiquent des audits de sécurité financés par deux utilisateurs industriels. Il est en production chez plusieurs d'entre eux, et propose un partage octet par octet sur GF(256).
- Écartés :
  - `sharks` : abandonné depuis 2021, avec un biais corrigé seulement dans son fork ;
  - `blahaj`, ce fork : non audité ;
  - `shamirsecretsharing` : liaison C plus ancienne, qui tire `rand` 0.8 en doublon ;
  - `gf256` : son auteur le présente comme pédagogique.
- `vsss-rs` n'ajoute que de petites crates sans doublon de version (`ff`, `subtle`, `rand_core`, `typenum`, `generic-array`, `hybrid-array`).
- **L'aléa des coefficients vient d'`aws-lc-rs`** : il est tiré à l'avance par `ostena-crypto`, puis servi à `vsss-rs`.

**6. Rotation annuelle** (à 2/3 de la validité), en une seule cérémonie :
1. sur le core, générer les nouvelles clés de la CA émettrice et du serveur ;
2. les faire certifier par la racine ;
3. installer le nouveau certificat serveur. Les agents l'acceptent tel quel : ils épinglent la racine ;
4. installer la nouvelle CA émettrice : le core émet avec elle et accepte les deux CA émettrices pendant le recouvrement ;
5. les certificats d'agent (30 jours) migrent d'eux-mêmes au renouvellement ;
6. après 30 jours plus une marge, retirer l'ancienne CA émettrice.

**7. Compromission de la CA émettrice** :
- **portée limitée** : seuls des certificats d'agent peuvent être forgés, et le registre refuse ceux qu'il n'a pas émis ;
- **réponse** : on retire la CA de l'ensemble accepté par le core (les tunnels qui en dépendent sont fermés), on en fait certifier une nouvelle par la racine, et les agents se ré-enrôlent avec un nouveau jeton.

**Compromission du certificat serveur** : il faut une cérémonie pour en certifier un nouveau, puis le révoquer. L'agent n'a pas de liste de révocation : jusqu'à l'expiration de l'ancien certificat (1 an au plus), un attaquant qui a volé sa clé peut usurper le core sur le réseau. **Cette limite est acceptée en v1.** Elle est inscrite aux [points à trancher](../points-a-trancher.md) du lot L15, avec ses deux pistes : une liste de révocation distribuée aux agents, ou des certificats serveur plus courts.

**8. Rotation de la racine** (10 ans, ou en cas de compromission) : il faut déposer la nouvelle racine sur chaque agent (`tls_core_ca`), selon une procédure documentée. Un futur message de contrôle pourrait la pousser, signée par l'ancienne racine.

**9. HSM** : la CA émettrice et la racine passeront en PKCS#11. L'interface de signature d'`ostena-crypto::pki` est prévue pour une clé non exportable.

**Alternative écartée** : une CA unique en ligne. Sa compromission permettrait d'usurper le core, et sa rotation impose de redéployer la CA sur tous les agents.

### Codes

| Code | Erreur |
|---|---|
| `TUN-E001` | groupe `SecP256r1MLKEM768` non négocié |
| `TUN-E002` | suite ou version non négociée |
| `TUN-E003` | CA inconnue, ou émetteur au nom de la CA mais avec une autre clé |
| `TUN-E004` | certificat expiré ou pas encore valide |
| `TUN-E005` | agent révoqué |
| `TUN-E006` | agent inconnu du registre |
| `TUN-E007` | aucun certificat client |
| `TUN-E008` | ALPN |
| `TUN-E009` | nom du core |
| `TUN-E010` | violation du protocole |
| `TUN-E011` | version |
| `TUN-E012` | heartbeat |
| `TUN-E013` | connexion perdue |
| `TUN-E014` | erreur locale |
| `TUN-E015` | configuration |
| `TUN-E016` | autre échec de poignée de main |
| `TUN-E017` | certificat du core non signé directement par la racine épinglée |
| `TUN-E018` | jeton d'enrôlement inconnu ou faux |
| `TUN-E019` | jeton d'enrôlement expiré |
| `TUN-E020` | jeton d'enrôlement déjà utilisé |
| `TUN-E021` | jeton émis pour un autre groupe |
| `TUN-E022` | preuve de possession invalide |
| `TUN-E023` | jeton brûlé après trois échecs |
| `TUN-E024` | jeu de clés de version inférieure à la dernière acceptée, même avant un redémarrage |
| `TUN-E025` | politique de version inférieure à celle appliquée |
| `TUN-E026` | session refusée : le core n'a pas encore poussé de politique ou de clés |
| `TUN-E027` | le core n'a pas répondu à la demande de session |
| `TUN-E028` | politique du core refusée (autre groupe, ou ne se compile pas en production) |
| `TUN-E029` | registre des agents (ou magasin des jetons) du core illisible : refus plutôt que copie périmée (ADR-0011) |
| `TUN-E030` | confiance SSH poussée par le core refusée (version inférieure à celle appliquée, ou même version avec un autre contenu) |

Événements : `tunnel.connected` (avec le transport), `tunnel.refused`, `tunnel.message_refused`, `tunnel.accept_failed` (écoute TCP du core) ; côté agent : `tunnel.fallback` (avertissement : repli sur TCP, et pourquoi), `agent.core_connected`, `agent.core_disconnected` (code, délai avant la tentative suivante), `agent.core_link_disabled`, `agent.renewal_requested`, `agent.certificate_renewed`, `agent.renewal_failed`, `agent.infrastructure_refreshed`, `agent.infrastructure_unresolved`, `agent.identity_rotated`, `agent.renewal_impossible`, `tunnel.renewal_overdue` (avertissement, répété chaque heure).

## Conséquences

- **Latence ajoutée** mesurée par `cargo bench -p ostena-tunnel` (aller-retour de 64 octets sur un canal interactif, comparé à TCP en boucle locale) : **22 µs au p99 sous Windows 11** et **140 µs au p99 sous Linux dans un conteneur Docker** (machine virtuelle WSL2, plus bruitée), pour un objectif indicatif de 1 ms. Le banc est affiché en CI sans seuil bloquant (ADR-0005).
- **Latence du repli TCP**, même banc (cas `round_trip_64_tcp`), le 2026-11-26 sous Linux (machine partagée à 4 cœurs, boucle locale) : **81 µs ajoutés au p99** (20 µs au p50), contre **21 µs** (14 µs au p50) pour QUIC sur la même machine. Le repli reste très en deçà de l'objectif de 1 ms ; l'écart vient surtout de la tâche d'écriture et du chiffrement TLS par lot. Sur un réseau avec pertes, TCP ajoute en plus le blocage en tête de ligne entre flux, que le banc en boucle locale ne mesure pas.
- **Le core de test** est derrière la fonctionnalité `testing`. `cargo xtask check-release` échoue si elle est activée dans le binaire de release ou si le binaire contient son marqueur ; les jobs de build le vérifient.
- **Repli TCP** : `tokio-rustls` (déjà lié au core et à l'agent pour l'API de connexion, ADR-0015) est autorisé dans `ostena-tunnel` ; il ne fait que porter la configuration d'`ostena-crypto::tls`. Aucune nouvelle crate. Le pare-feu du core doit ouvrir le port 8443 en TCP en plus d'UDP.
- **Nouvelle dépendance** : `quinn`, avec `quinn-proto`, `quinn-udp`, `socket2` et `rand` (identifiants de connexion, rien de cryptographique). `deny.toml` réserve `quinn` à `ostena-tunnel`.
- **Cible wasm32 retirée de `cargo deny`** : `quinn-proto` dépend de `ring` sous wasm32. `ostena-frame`, seule crate wasm, n'a aucune dépendance. Il faudra remettre cette cible, ciblée, avec `ostena-web-client`.
- **Windows Server 2016** : la pile UDP ancienne n'est pas couverte en CI. L'essai S5 vérifie le tunnel QUIC et le repli TCP (fiche d'installation, lot L2, PR 6).
