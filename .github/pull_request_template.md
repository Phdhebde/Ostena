## Objet

<!-- Ce que change la PR et pourquoi. Lien vers le ticket ou l'ADR. -->

## Validation

<!-- Commandes lancées et résultats (Linux, Windows, PostgreSQL si concerné). -->

## Liste de contrôle

- [ ] Chaque commit porte un `Signed-off-by` (DCO, `git commit -s`)
- [ ] `cargo xtask ci` passe en local
- [ ] Tests ajoutés ou mis à jour ; cible de fuzz pour tout nouvel analyseur de données réseau
- [ ] Toute nouvelle dépendance est justifiée ci-dessus et passe `cargo deny check`
- [ ] Événements d'audit émis et documentés, si la PR en ajoute
- [ ] Documentation à jour ; un ADR pour un choix structurant
