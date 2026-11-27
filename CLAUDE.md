# CLAUDE.md — Aplomb

**Le document de référence du projet est [docs/STRUCTURE.md](docs/STRUCTURE.md).** Lis-le avant toute tâche : il fixe le périmètre, les choix techniques, l'architecture (§ 7) et l'ordre des étapes (§ 12). En cas de doute, c'est lui qui tranche ; si un choix doit s'en écarter, demande d'abord.

## Suivi obligatoire dans docs/STRUCTURE.md

À la fin de chaque étape :

1. **Coche l'étape terminée** dans le § 12 (`- [ ]` → `- [x]`), et coche aussi les questions ouvertes du § 13 qui ont été résolues.
2. **Complète le « Journal des décisions »** en fin de fichier : une ligne datée (`- **AAAA-MM-JJ** — …`) par décision prise ou écart par rapport au cadrage.
3. Mets à jour le statut en tête du fichier si besoin.

Ne réalise qu'une étape à la fois et arrête-toi à la fin de l'étape demandée ; chaque étape doit se terminer par un exe Windows testable (`make windows`).

## Conventions

- Go installé dans `/usr/local/go` ; `export PATH=$PATH:/usr/local/go/bin` si `go` n'est pas trouvé.
- Module : `github.com/maxb1906/aplomb`. Pas de CGO (`CGO_ENABLED=0`), dépendances pures Go uniquement (Wails l'est sous Windows ; il n'est importé que dans `internal/gui/run_windows.go`).
- Interface graphique (v2) : `frontend/` (Svelte 5 + Vite + TS), compilée par `make frontend` (Node.js LTS) et embarquée ; la logique reste en Go (`internal/app`, `internal/gui`). `make mock` puis `cd frontend && npm run dev` pour la voir dans un navigateur.
- **Lecture seule** : aucun code ne doit écrire dans le registre, les services, les tâches ou la stratégie de la machine auditée. Seuls le rapport et `aplomb-data/` sont écrits, à côté de l'exe.
- **Pas de PowerShell en coulisse** : API Windows natives (registre, WMI/COM, NetAPI, Task Scheduler). PowerShell n'apparaît que dans les remédiations du rapport.
- **Pas de CIS** : ni contenu, ni identifiants, ni mention de conformité.
- Code propre à Windows dans des fichiers `_windows.go` (ou `//go:build windows`), avec un équivalent `_other.go` pour que tout compile et se teste sur la devbox Linux ARM64.
- **Aucune chaîne utilisateur en dur** : toute chaîne passe par `internal/i18n` et des clés présentes dans `assets/i18n/fr.json` **et** `en.json` (le test `TestEmbeddedCatalogsAreComplete` échoue sinon) ; dans le frontend, `t('gui.…')` avec une clé littérale (vérifiée par `TestUsedKeysExist`).
- Avant de pousser : `make fmt-check vet test build-all`.
