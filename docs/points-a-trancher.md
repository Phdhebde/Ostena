# Points à trancher, par lot

Questions ouvertes laissées volontairement en suspens, avec le lot où elles seront traitées. Chaque point renvoie à l'ADR qui l'a soulevé. Une fois tranché, il quitte cette liste pour entrer dans un ADR.

## Lot L15 — Industrialisation : HA, appliance, sauvegarde, mises à jour signées, documentation

### Révocation du certificat serveur du core

Soulevé par l'[ADR-0008](adr/0008-tunnel-agent-core-et-enrolement.md) (clé de la CA du core, compromission du certificat serveur).

**Situation en v1, acceptée.** Les agents n'acceptent qu'un certificat du core signé directement par la racine hors ligne, valide 1 an, mais ils n'ont pas de liste de révocation. Si la clé de ce certificat est volée, l'attaquant peut usurper le core auprès des agents jusqu'à l'expiration du certificat, même après une cérémonie qui en certifie un nouveau.

**Pistes :**
1. **Distribuer une liste de révocation aux agents**, signée par la racine lors des cérémonies et poussée par le tunnel ou déposée avec la configuration. L'agent refuserait un certificat serveur listé.
   - Inconvénient : la racine doit signer périodiquement, ou la liste ne contient que des révocations ponctuelles décidées en cérémonie.
2. **Raccourcir les certificats serveur** (de l'ordre d'une semaine à un mois) pour borner la fenêtre d'usurpation.
   - Inconvénient : la racine étant hors ligne, il faudrait soit des cérémonies fréquentes, soit une délégation contrainte, par exemple un intermédiaire limité au seul nom du core et à l'EKU serverAuth, ce qui revient à réintroduire une CA serveur en ligne.
