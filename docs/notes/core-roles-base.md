# Note : séparer les rôles DDL et DML de la base du core

- **Statut** : traitée au jalon M2 (PR 3, 2026-11-26).
- **Décision** : [ADR-0011](../adr/0011-socle-du-core-et-postgresql.md), section « Rôles de la base » ; procédure dans l'[installation du core](../exploitation/core-installation.md).

La note décrivait la séparation reportée après M1 : un propriétaire du schéma utilisé seulement par `ostena core migrate`, un rôle du service limité aux droits DML, `SELECT` et `INSERT` seulement sur la chaîne d'audit, et deux comptes système pour garder l'authentification `peer`. C'est ce que fait l'amendement de l'ADR-0011 (`ostena_owner`, `ostena_app`, comptes `ostena` et `ostena_admin`, `ostena core db init`).

Elle reste en place parce que la migration `0002_audit_chain.sql`, dont le texte ne peut plus changer (sa somme de contrôle est enregistrée dans les bases), renvoie vers elle.
