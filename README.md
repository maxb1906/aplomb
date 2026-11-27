# Aplomb

**Français** · [English](README.en.md)

[![CI](https://github.com/maxb1906/aplomb/actions/workflows/ci.yml/badge.svg)](https://github.com/maxb1906/aplomb/actions/workflows/ci.yml)
[![Licence : GPL-3.0](https://img.shields.io/badge/licence-GPL--3.0-blue.svg)](LICENSE)

Outil **portable** d'audit de la configuration de sécurité d'un poste ou serveur **Windows**. Un seul exécutable, sans installation ni PowerShell en coulisse : lancez-le sur la machine, il vérifie en quelques secondes ses failles de configuration locales et produit un **rapport** avec un score de conformité et, pour chaque problème, une explication simple et la commande PowerShell de correction.

Pensé pour les techniciens, indépendants et MSP qui interviennent dans des PME. Complémentaire d'[Arpent](https://github.com/maxb1906/arpent) : Arpent audite le réseau, Aplomb audite l'intérieur de chaque machine.

## ⚖️ Lecture seule et cadre d'utilisation

Aplomb est un outil de **contrôle de conformité en lecture seule** : il **ne modifie jamais** la machine auditée et n'exploite aucune faille. Il est destiné à l'administrateur de la machine ou à un prestataire mandaté par son propriétaire.

Le rapport contient des informations sensibles (comptes, chemins, faiblesses) : traitez-le comme un document **confidentiel** et ne le laissez pas traîner sur une clé USB.

## Ce qu'Aplomb vérifie (57 règles)

| Catégorie | Exemples de contrôles |
|---|---|
| **Durcissement système** (13) | UAC, AlwaysInstallElevated, RDP sans NLA, LLMNR, NetBIOS, WDigest, protection LSA, Credential Guard, PowerShell 2.0, journalisation PowerShell, AutoRun, mises à jour, Secure Boot |
| **Services** (5) | chemins sans guillemets exploitables, binaires/dossiers/clés de registre modifiables par des non-admins, service SYSTEM lancé depuis un dossier utilisateur, spouleur inutile sur serveur/DC |
| **Tâches planifiées** (5) | tâche privilégiée lançant un fichier modifiable, emplacements à risque, commandes suspectes (PowerShell encodé, mshta, certutil…), tâches masquées, orphelines |
| **Comptes et mots de passe** (10) | longueur minimale, verrouillage, expiration, complexité, Invité, Administrateur intégré, membres du groupe Administrateurs, comptes sans mot de passe, LAPS |
| **BitLocker** (6) | disque système et volumes de données non chiffrés, protection suspendue, TPM seul sur portable, mot de passe de récupération, sauvegarde imposée |
| **Microsoft Defender** (7) | temps réel, protection contre les falsifications, signatures, exclusions trop larges, cloud, PUA, règles ASR |
| **Partages SMB** (6) | partages ouverts à tous en écriture/lecture (droits de partage **et** NTFS), SMBv1 serveur et client, signature, accès invité |
| **Pare-feu Windows** (5) | profils désactivés, action entrante « Autoriser », règles tout/tout, ports sensibles ouverts sur le profil Public, programmes modifiables |

`aplomb rules` liste toutes les règles. Elles sont définies dans [assets/rules.yaml](assets/rules.yaml) (règles maison ; références indicatives Microsoft, ANSSI et MITRE ATT&CK).

Chaque règle s'applique selon le **profil** de la machine (poste, serveur membre, contrôleur de domaine), détecté automatiquement. Les niveaux sont **Info / Attention / Critique**, nuancés pour éviter les faux positifs (ex. un chemin sans guillemets n'est Critique que si un dossier intermédiaire est réellement inscriptible). Si un paramètre est imposé par **GPO ou Intune**, le rapport le signale : la correction doit se faire dans la stratégie.

## Démarrage

1. Téléchargez `aplomb_<version>_windows_amd64.zip` depuis les [Releases](https://github.com/maxb1906/aplomb/releases) et décompressez-le sur une clé USB.
2. Lancez `aplomb.exe` : l'**interface graphique** s'ouvre. Si vous n'êtes pas administrateur, le bouton « Relancer en administrateur » donne un audit complet. Cliquez sur « Lancer l'audit » : il dure quelques secondes.
3. Les rapports sont rangés à côté de l'exécutable, un dossier par machine :

```
aplomb.exe
aplomb-data/
├── config.yaml
├── webview2/                                 # cache de la fenêtre (interface graphique)
└── rapports/
    └── PC-ACCUEIL-01/
        ├── 2026-11-25_1430.html              # rapport autonome, imprimable en PDF
        ├── 2026-11-25_1430.md                # même contenu, pour un ticket ou un wiki
        ├── 2026-11-25_1430.json              # résultats bruts + données collectées
        └── 2026-11-25_1430_remediation.ps1   # corrections, toutes commentées
```

Sans droits administrateur, Aplomb fonctionne en **mode dégradé** : les contrôles impossibles (BitLocker, exclusions Defender, droits des partages, protection LSA…) sont marqués « non vérifiés », exclus du score, et le taux de couverture est indiqué.

> **SmartScreen / antivirus** : l'exécutable n'est pas encore signé. Windows peut afficher « Windows a protégé votre ordinateur » : « Informations complémentaires » puis « Exécuter quand même ». Vérifiez l'empreinte avec le fichier `SHA256SUMS` de la release.

## Interface graphique

Sans argument, `aplomb.exe` ouvre une fenêtre (Wails + WebView2) :

- **Audit** : machine, élévation (bouton « Relancer en administrateur »), profil et langue du rapport, progression section par section ;
- **Résultats** : score, note et résumé, problèmes classés par gravité avec filtres (niveau, catégorie, recherche), détail de chaque contrôle, objets concernés, commande de correction à copier, contrôles non vérifiés, détail par catégorie ; boutons vers le rapport HTML, le script de remédiation et le dossier ;
- **Accepter un risque** depuis un problème : la justification est enregistrée dans `config.yaml` et le rapport est régénéré ;
- **Historique** de tous les rapports d'`aplomb-data` (plusieurs machines : une clé USB, dix postes) ;
- **Réglages** : technicien, société, logo, langues, profil, formats, règles désactivées.

L'interface produit exactement les mêmes fichiers que la ligne de commande. Elle s'appuie sur le composant **Microsoft Edge WebView2**, présent sur Windows 10/11 et Windows Server 2025 ; s'il manque (Windows Server 2016 à 2022 sans Edge), Aplomb fait l'audit **en console**, comme la v1. `aplomb.exe audit` force toujours la console.

## Score

Score sur 100, global et par catégorie : chaque contrôle vérifié pèse 10 (Critique), 4 (Attention) ou 1 (Info) ; score = poids des contrôles conformes / poids des contrôles vérifiés. Note A (≥ 90) à E (< 40). **Un seul problème Critique plafonne la note à C** (score ramené à 74 au plus ; le score brut figure dans le rapport).

## Remédiation

Pour chaque problème, le rapport donne une commande PowerShell prête à copier et prévient de son impact (redémarrage, compatibilité…). Le script `…_remediation.ps1` regroupe toutes les corrections, **chacune commentée** : décommentez celles que vous retenez, puis lancez-le en administrateur sur la machine auditée (il refuse de tourner ailleurs). `-WhatIf` simule, et tout est journalisé dans un `.log` à côté du script. Les corrections d'un paramètre imposé par GPO sont précédées de `##` : corrigez plutôt la stratégie.

## Ligne de commande

```
aplomb                                    # interface graphique (par défaut ; console si WebView2 est absent)
aplomb audit                              # audit en console et ouverture du rapport
aplomb audit --out D:\rapports --format html,md,json,ps1 --report-lang en --profile serveur --no-open
aplomb config --technician "Nom" --company "Ma société" --logo logo.png
aplomb collect --out machine.json         # données brutes, sans évaluation
aplomb evaluate --input machine.json      # rapport à partir de données enregistrées (aussi sous Linux/macOS)
aplomb rules | host | version | help      # aplomb <commande> -h pour les options
```

Options globales : `--lang fr|en` et `--data <dossier>` (ou variable `APLOMB_DATA`).

## Configuration

`aplomb-data/config.yaml` (créé au premier audit) : technicien, société et logo de la page de garde, langues de l'outil et du rapport, profil forcé, formats, et **règles désactivées** — leur défaut apparaît alors comme « risque accepté » avec la justification :

```yaml
disabled_rules:
  - id: SMB-003
    reason: "Copieur ancien en SMBv1, remplacement prévu en 2027"
```

## Compilation et tests

Prérequis : [Go](https://go.dev/dl/) (version de `go.mod`) et [Node.js](https://nodejs.org/) LTS pour l'interface graphique (`frontend/`, Svelte). Aucun CGO : la cross-compilation vers Windows fonctionne depuis Linux ou macOS.

```sh
make test        # tests (règles, score, rapports sur des fixtures JSON)
make windows     # dist/aplomb-windows-amd64.exe (compile aussi l'interface et les ressources : icône, manifeste)
make build-all   # windows/amd64 et windows/arm64
make all         # format, vet (Linux et Windows), tests, binaires
make mock && (cd frontend && npm run dev)   # interface dans un navigateur, avec des données de démonstration
```

La CI exécute aussi l'exe sur Windows Server (dont l'ouverture de la fenêtre), vérifie la syntaxe des scripts de remédiation avec PowerShell 5.1 et 7, et rejoue le [laboratoire](lab/README.md) : une machine rendue volontairement vulnérable doit voir chaque faiblesse détectée. Les versions sont publiées par GoReleaser à chaque tag `vX.Y.Z`.

## Contribuer

- Règles : `assets/rules.yaml` (textes FR/EN, remédiation) et `internal/checks/<catégorie>/` (logique) ; chaque règle doit avoir les deux, ce que vérifient les tests.
- Traductions : `assets/i18n/fr.json` et `en.json` (mêmes clés, vérifié par les tests), y compris celles de l'interface graphique (`t('gui.…')` dans `frontend/src`).
- Cadrage et décisions : [docs/STRUCTURE.md](docs/STRUCTURE.md).

## Licence

[GPL-3.0](LICENSE).
