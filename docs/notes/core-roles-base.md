# Note : séparer les rôles DDL et DML de la base du core

- **Statut** : reporté après le jalon M1 (décision du 2026-11-14).
- **Origine** : [ADR-0011](../adr/0011-socle-du-core-et-postgresql.md).

En M1, le core se connecte avec un seul rôle, propriétaire du schéma : il applique lui-même les migrations au démarrage. Un core compromis peut donc modifier le schéma, par exemple supprimer une table d'audit ou un déclencheur d'ajout seul.

**Cible** : deux rôles.
- `ostena_owner` possède le schéma et n'est utilisé que par `ostena core migrate`, lancé par l'exploitant lors d'une mise à jour.
- `ostena_app` n'a que les droits DML nécessaires, table par table. Sur la chaîne d'audit, ce sera `INSERT` et `SELECT` seulement, pour renforcer l'ajout seul de la PR 3.

**Difficulté avec `peer`** : l'authentification `peer` associe un compte système à un rôle du même nom. Deux rôles demandent donc :
- soit deux comptes système (`ostena` pour le service, `ostena-admin` pour les migrations) ;
- soit une table `pg_ident.conf` qui autorise un compte système à prendre l'un ou l'autre rôle, ce qui affaiblit la séparation.

La première option est la plus simple à auditer.

**Conséquences à prévoir** :
- `ostena core run` ne migre plus : il vérifie le schéma (`CORE-E005`) et refuse s'il n'est pas à jour ;
- la procédure de mise à jour passe par `ostena core migrate` sous le compte d'administration ;
- les migrations accordent explicitement les droits à `ostena_app`.
