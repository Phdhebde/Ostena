# ADR-0003 : Format et validation de la configuration

- **Statut** : Accepté
- **Date** : 2026-11-11
- **Révisé** : 2026-11-11 — section `[agent]` (`CFG-V006` à `V010`, `CFG-P007` à `P010`) et `CFG-P006` sous Windows

## Contexte

Le bastion doit refuser de démarrer dans une configuration qui affaiblit sa sécurité, tout en restant utilisable en laboratoire. Une erreur de frappe dans un fichier de configuration ne doit pas passer inaperçue. Les secrets ne doivent jamais apparaître dans un journal. Une évaluation CSPN demandera de montrer ces garanties et leurs limites.

## Décision

### Format

- Un **fichier TOML unique**, lu par `ostena_common::config::load`.
- **Désérialisation stricte** : `deny_unknown_fields` sur toutes les structures, y compris les variantes des destinations de journaux. `Stdout` est une variante struct vide (`Stdout {}`), car serde ignore les champs inconnus sur une variante unitaire d'enum à tag interne. Pas de `#[serde(flatten)]`, qui désactive ce contrôle.
- **Défauts sûrs** : un fichier vide donne une configuration valide en production. Mode `production`, `ssh.host_key_verification = "strict"`, `rdp.certificate_validation = "pinned"`, pas de repli NTLM, grants `ed25519`, transport syslog `tls`.
- Les options dangereuses n'existent pas quand elles n'ont aucun usage légitime : par exemple, il n'y a pas de valeur `off` pour la vérification de clé hôte SSH.
- **Aucun secret dans la configuration.** Un secret est référencé par un chemin et chargé dans un `Secret<…>` à l'usage. `Config` reste donc `Debug` sans risque : un champ `Secret` ne pourrait pas y être ajouté sans casser `derive(Debug)`, ce que prouve un test trybuild.

### Validation à deux niveaux

- `Config::validate()` : règles de cohérence (`CFG-V…`), appliquées dans tous les modes.
- `Config::validate_for_production()` : cohérence plus refus des options qui affaiblissent la sécurité (`CFG-P…`).
- `load()` applique les deux selon le mode et ajoute le contrôle des droits du fichier (`CFG-P006`). En développement, les affaiblissements sont acceptés et retournés pour être journalisés en `warn`, avec l'événement `config.weakening` et le champ `code`.
- **Toutes les violations sont rapportées d'un coup**, dans l'ordre des règles, chacune avec un message en français qui nomme le champ en cause.
- **Aucune résolution DNS** pendant la validation : seule une adresse de boucle locale littérale (127.0.0.0/8, ::1, y compris sous la forme ::ffff:127.x) est considérée comme locale. `localhost` est traité comme distant.

### Codes stables

Les codes font partie de l'interface du produit. Ils ne sont jamais renumérotés ni réutilisés ; on en ajoute.

| Code | Niveau | Signification |
|---|---|---|
| `CFG-E001` | lecture | fichier illisible |
| `CFG-E002` | lecture | TOML invalide, champ inconnu ou valeur hors domaine |
| `CFG-V001` | cohérence | `certificate_validation = "pki"` sans `pki_ca_bundle` |
| `CFG-V002` | cohérence | `pki_ca_bundle` renseigné sans validation `pki` |
| `CFG-V003` | cohérence | chemin vide |
| `CFG-V004` | cohérence | algorithme de signature de grant inconnu |
| `CFG-V005` | cohérence | adresse syslog invalide |
| `CFG-P001` | production | vérification de clé hôte SSH non stricte (`accept-new`) |
| `CFG-P002` | production | certificat RDP des cibles ni épinglé ni validé par une PKI |
| `CFG-P003` | production | repli NTLM autorisé alors qu'un mot de passe est délégué |
| `CFG-P004` | production | algorithme de signature de grant autre qu'Ed25519 |
| `CFG-P005` | production | journaux ou audit envoyés en clair (syslog UDP/TCP) vers une autre machine |
| `CFG-P006` | production | fichier de configuration ou son dossier modifiable par un autre compte que root ou le compte du service |
| `CFG-V006` | cohérence | `agent.gateway_group` n'est pas un UUID |
| `CFG-V007` | cohérence | `agent.core_address` invalide (hôte:port attendu) |
| `CFG-V008` | cohérence | chemin de l'agent non absolu |
| `CFG-V009` | cohérence | délai d'arrêt (1 à 300 s) ou nombre de threads (1 à 64) hors bornes |
| `CFG-V010` | cohérence | déclaration d'infrastructure invalide, ou composants Ostena placés dans `agent.scope.infrastructure` au lieu de `[[agent.infrastructure]]` |
| `CFG-P007` | production | pas de CA dédiée au certificat du core (`agent.tls_core_ca`) |
| `CFG-P008` | production | clé privée de l'agent lisible ou modifiable par un autre compte que le service ou les administrateurs |
| `CFG-P009` | production | dossier du journal anti-rejeu modifiable par un autre compte |
| `CFG-P010` | production | nom d'infrastructure impossible à résoudre au démarrage |

`CFG-P006` sous Unix : le fichier (après résolution des liens symboliques) et son dossier doivent appartenir à root ou au compte du service, sans droit d'écriture pour le groupe ni pour les autres. Le compte du service est le propriétaire de `/proc/self`, ce qui évite un appel FFI `unsafe`. S'il est indisponible, seul root est accepté.

`CFG-P006` sous Windows : le propriétaire et la DACL du fichier et de son dossier sont lus par `ostena-platform` (API Win32, seul crate autorisé à contenir de l'`unsafe`). Seuls SYSTEM, les Administrateurs, TrustedInstaller et le compte du service (`NT SERVICE\OstenaAgent`) peuvent en être propriétaires ou y écrire ; les entrées de refus et celles qui ne s'appliquent qu'aux enfants sont ignorées ; une DACL nulle ou un type d'entrée inconnu est refusé. Les comptes intégrés sont identifiés par leur SID, jamais par leur nom (traduit selon la langue de Windows). La vérification est injectée par un trait (`PermissionChecker`) : `load()` garde la vérification par défaut, qui refuse sous Windows, et l'agent utilise `load_with(chemin, ostena_platform::permission_checker())`.

**Section `[agent]`** (détails dans l'ADR-0007) : identifiant du groupe de passerelles, adresse du core, certificat, clé privée (chargée dans un `Secret`) et CA dédiée du core, journal anti-rejeu, délai d'arrêt, threads de travail (par défaut min(4, cœurs)), politique de périmètre et composants Ostena. Les types de données de la politique de périmètre vivent dans `ostena-common` pour que tout le fichier soit analysé en une seule passe stricte ; `ostena-scope` les réexporte et les compile. `CFG-P008` et `CFG-P009` passent par le même `PermissionChecker` : la clé privée doit être réservée au compte du service (Unix : mode 600 au plus), le dossier du journal ne doit être modifiable que par lui.

### Secrets et journaux

- `Secret<T>` enveloppe `secrecy::SecretBox` (valeur sur le tas, effacée à la libération). Il n'implémente ni `Debug`, ni `Display`, ni `Clone`, ni `Serialize`, ni conversion vers `String`. Des tests trybuild prouvent que `{}`, `{:?}`, `.to_string()`, `String::from`, `.into()`, `tracing::info!(x = ?s)`, `%s`, `.clone()` et `derive(Debug)` sur un type qui contient un secret ne compilent pas.
- `expose_secret` et `expose_secret_mut` sont des `disallowed-methods` de clippy. Chaque usage porte `#[expect(clippy::disallowed_methods)]` juste sous un commentaire `// SECRET-EXPOSURE: raison`. `cargo xtask check-secrets`, lancé en CI, refuse une exemption sans justification, un `allow` au lieu d'un `expect`, et un attribut interne de portée module.
- Les journaux sont écrits en JSON par une couche `tracing` maison, sans `env-filter` ni `regex`. Elle remplace par `[REDACTED]` la valeur de tout champ d'événement ou de span dont le nom contient un fragment sensible (`password`, `secret`, `token`, `key`, `credential`, `authorization`, `cookie`, `private`, `session_id`, `otp`, `pin`…), quel que soit son type.
- Un test canari fait passer un secret reconnaissable par les chemins protégés et vérifie qu'il n'apparaît jamais dans la sortie. Ces chemins sont : un champ au nom sensible (événement et span), une structure contenant un secret journalisée sous un nom anodin (avec un `Debug` manuel qui utilise `Secret::redacted()`), et le `Debug` de `Config`.

## Conséquences

### Limites assumées

- **On ne peut pas garantir qu'aucun secret n'apparaît jamais dans les journaux.** Une valeur sortie par `expose_secret()` puis journalisée sous un nom de champ anodin, ou insérée dans le texte du message (`info!("… {}", valeur)`), est écrite en clair. Le masquage par nom ne voit pas les valeurs. Un test (`known_limit_exposed_value_under_harmless_name_is_not_redacted`) fige cette limite ; s'il échoue un jour, la protection a progressé et cet ADR doit être mis à jour. Les garde-fous sont la revue de chaque `SECRET-EXPOSURE` et `check-secrets`.
- `check-secrets` lit le code ligne à ligne, ce n'est pas un analyseur syntaxique : c'est une aide à la revue. L'interdiction elle-même est appliquée par clippy.
- Le masquage par nom produit des faux positifs (`pinned`, `keyboard_…`) : on préfère masquer trop que pas assez.
- `CFG-P002` porte sur la politique globale. Les empreintes épinglées par cible vivront dans l'inventaire du core, et le driver RDP devra refaire le contrôle à l'exécution.
- `CFG-P005` ne voit pas un fichier de journal posé sur un montage réseau non chiffré (NFS, SMB).
- `CFG-P006` ne contrôle que le fichier et son dossier immédiat, pas toute l'arborescence. Si le processus n'est pas « dumpable », `/proc/self` appartient à root : seul un fichier appartenant à root est alors accepté (refus par défaut).
- **Windows** : `CFG-P006` est implémenté dans `ostena-platform` (voir plus haut). Sans le vérificateur de la plateforme, `load()` refuse toujours la production sous Windows.
- Les destinations syslog sont validées mais pas encore implémentées. L'initialisation des journaux renvoie `LOG-E002` tant qu'`ostena-audit` n'existe pas.

### Autres conséquences

- Les dépendances ajoutées (`serde`, `toml`, `tracing`, `tracing-subscriber` limité à `registry`, `serde_json`, `secrecy`, `zeroize`, `thiserror`) imposent l'exception de licence `Unicode-3.0` pour `unicode-ident` (voir `deny.toml`). La fonctionnalité `attributes` de `tracing` est désactivée (pas de `#[instrument]`) pour éviter une seconde version majeure de `syn`.
- Les fichiers `.stderr` de trybuild dépendent de la version du compilateur. Ils sont à régénérer (`TRYBUILD=overwrite`) et à relire à chaque montée de toolchain.
