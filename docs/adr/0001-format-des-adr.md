# ADR-0001 : Format des ADR

- **Statut** : Accepté
- **Date** : 2026-11-11

## Contexte

Ostena vise une évaluation CSPN. Les évaluateurs comme les futurs contributeurs doivent pouvoir retrouver pourquoi un choix structurant a été fait, sans fouiller l'historique des commits ou des discussions.

## Décision

Chaque choix structurant fait l'objet d'un ADR (*Architecture Decision Record*) dans `docs/adr/`, rédigé en français.

- Nom de fichier : `NNNN-titre-court-en-kebab-case.md`, numéro sur quatre chiffres, croissant, jamais réutilisé.
- En-tête : titre `# ADR-NNNN : Titre`, puis **Statut** (`Proposé`, `Accepté`, `Remplacé par ADR-XXXX`, `Abandonné`) et **Date**.
- Trois sections, courtes :
  - **Contexte** : le problème, les contraintes, les forces en présence ;
  - **Décision** : ce qui est retenu, à l'indicatif présent ;
  - **Conséquences** : ce que cela implique, y compris les inconvénients acceptés.
- Un ADR accepté n'est plus modifié sur le fond : pour revenir sur une décision, on écrit un nouvel ADR qui remplace l'ancien, et on met à jour le statut de l'ancien.
- L'ADR est livré dans la même pull request que le changement qu'il justifie, et ajouté à l'index `docs/adr/README.md`.

## Conséquences

- La trace des décisions est versionnée avec le code et relue en revue.
- Le format court limite le coût d'écriture ; une page suffit dans la plupart des cas.
- Les ADR remplacés restent consultables, ce qui conserve l'historique du raisonnement.
