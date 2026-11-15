# Points à trancher, par lot

Questions ouvertes laissées volontairement en suspens, avec le lot où elles seront traitées. Chaque point renvoie à l'ADR qui l'a soulevé. Une fois tranché, il quitte cette liste pour entrer dans un ADR.

## Lot L6 — Audit

Points soulevés par l'[ADR-0012](adr/0012-chaine-d-audit-du-core.md) (chaîne d'audit du core).

### Têtes hybrides post-quantiques

**Situation en M1.** Les têtes sont signées par ECDSA P-256 seul. Une tête doit rester vérifiable des années, et l'ADR-0009 prévoit ECDSA P-256 + ML-DSA-65 pour les têtes de chaîne d'audit.

**Piste :** une tête de version 2, avec son propre identifiant d'algorithme, portant les deux signatures concaténées ; les enregistrements ne changent pas, le vérificateur accepte les deux versions.
- Bloquant : ML-DSA n'est exposé par `aws-lc-rs` que derrière une fonctionnalité instable (ADR-0009).

### Ancrage externe des têtes : syslog, SIEM

**Situation en M1.** Les têtes sortent du core par le journal (`audit.head_signed`) et par `ostena core audit head`, relevée à la main ([procédure](exploitation/audit-verification.md)). Rien ne garantit qu'une copie existe hors du bastion.

**Pistes :**
1. Envoyer chaque tête à un syslog distant ou à un SIEM (export OCSF prévu par l'architecture), et le documenter comme ancre : `ostena audit verify --head` lirait les têtes depuis l'export de ce SIEM.
2. Compter les têtes envoyées et non acquittées, et alerter.

### Suivi d'une rotation de clé à la vérification (`--follow-rotation`)

**Situation en M1.** Après un changement de clé de signature, le core ancre son contrôle sur la dernière tête de l'ancienne clé, dont il lit la clé publique dans `audit.signing_started`. L'auditeur, lui, doit fournir toutes les clés (`--key` répété).

**Piste :** une option `--follow-rotation` qui accepte une nouvelle clé annoncée par un `audit.signing_started` lui-même couvert par une tête d'une clé déjà de confiance. À trancher : une clé annoncée ainsi vaut-elle une clé remise par un canal sûr ?

### Horodatage RFC 3161

**Situation en M1.** La trame d'export de type 3 est réservée et refusée par le vérificateur v1. Sans tiers horodateur, un core compromis peut réécrire ce qu'aucune tête externe ne couvre encore.

**Pistes :** horodater périodiquement le hash de tête auprès d'une autorité interne du client (fonctionne hors ligne si elle est sur site), stocker les jetons en base et les placer dans l'export ; le vérificateur v2 les contrôle avec la chaîne de l'autorité.

### Troncature sous la dernière tête

**Situation en M1.** Si des enregistrements sont supprimés sous la dernière tête signée (tête conservée), les nouveaux ajouts réutilisent leurs seq, et l'acquittement de la rupture n'est accepté qu'une fois la chaîne repassée au-delà du seq couvert par cette tête. À trancher : démarrer une nouvelle chaîne (nouvel identifiant) liée à l'ancienne par un enregistrement dédié ?

## Lot L15 — Industrialisation : HA, appliance, sauvegarde, mises à jour signées, documentation

### Révocation du certificat serveur du core

Soulevé par l'[ADR-0008](adr/0008-tunnel-agent-core-et-enrolement.md) (clé de la CA du core, compromission du certificat serveur).

**Situation en v1, acceptée.** Les agents n'acceptent qu'un certificat du core signé directement par la racine hors ligne, valide 1 an, mais ils n'ont pas de liste de révocation. Si la clé de ce certificat est volée, l'attaquant peut usurper le core auprès des agents jusqu'à l'expiration du certificat, même après une cérémonie qui en certifie un nouveau.

**Pistes :**
1. **Distribuer une liste de révocation aux agents**, signée par la racine lors des cérémonies et poussée par le tunnel ou déposée avec la configuration. L'agent refuserait un certificat serveur listé.
   - Inconvénient : la racine doit signer périodiquement, ou la liste ne contient que des révocations ponctuelles décidées en cérémonie.
2. **Raccourcir les certificats serveur** (de l'ordre d'une semaine à un mois) pour borner la fenêtre d'usurpation.
   - Inconvénient : la racine étant hors ligne, il faudrait soit des cérémonies fréquentes, soit une délégation contrainte, par exemple un intermédiaire limité au seul nom du core et à l'EKU serverAuth, ce qui revient à réintroduire une CA serveur en ligne.
