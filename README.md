# Aplomb

**Français** · [English](README.en.md)

[![CI](https://github.com/maxb1906/aplomb/actions/workflows/ci.yml/badge.svg)](https://github.com/maxb1906/aplomb/actions/workflows/ci.yml)
[![Licence : GPL-3.0](https://img.shields.io/badge/licence-GPL--3.0-blue.svg)](LICENSE)

Outil **portable** d'audit de la configuration de sécurité d'un poste ou serveur **Windows**. Un seul exécutable, sans installation : lancez-le sur la machine, il vérifie en quelques secondes ses failles de configuration locales et produit un **rapport** avec un score de conformité et, pour chaque problème, une explication simple et la commande PowerShell de correction.

Pensé pour les techniciens, indépendants et MSP qui interviennent dans des PME. Complémentaire d'[Arpent](https://github.com/maxb1906/arpent) : Arpent audite le réseau, Aplomb audite l'intérieur de chaque machine.

> 🚧 **En cours de développement** — rien d'utilisable pour l'instant. L'avancement est suivi dans [docs/STRUCTURE.md](docs/STRUCTURE.md).

## Ce qu'Aplomb vérifiera (v1)

- **Services** : chemins sans guillemets exploitables, binaires, dossiers et clés de registre modifiables par des non-administrateurs.
- **Tâches planifiées** : tâches SYSTEM pointant vers des fichiers inscriptibles, lignes de commande suspectes, tâches orphelines.
- **Comptes et mots de passe** : politique de mots de passe et de verrouillage, comptes Invité et Administrateur, membres du groupe Administrateurs, LAPS.
- **BitLocker** : volumes non chiffrés ou suspendus, protecteurs.
- **Microsoft Defender** : protection en temps réel, protection contre les falsifications, signatures, exclusions trop larges.
- **Partages SMB** : partages ouverts à tous, SMBv1, signature SMB, accès invité.
- **Pare-feu Windows** : profils désactivés, règles entrantes trop permissives, ports sensibles exposés.
- **Durcissement système** : UAC, RDP sans NLA, LLMNR/NetBIOS, WDigest, protection LSA, mises à jour, Secure Boot…

Rapport HTML autonome, Markdown et JSON, en **français ou en anglais**, avec un script de remédiation `.ps1` dont chaque bloc est commenté par défaut.

## ⚖️ Lecture seule et cadre d'utilisation

Aplomb est un outil de **contrôle de conformité en lecture seule** : il **ne modifie jamais** la machine auditée et n'exploite aucune faille. Il est destiné à l'administrateur de la machine ou à un prestataire mandaté par son propriétaire.

Le rapport contient des informations sensibles (comptes, chemins, faiblesses) : traitez-le comme un document **confidentiel** et ne le laissez pas traîner sur une clé USB.

Aplomb fonctionne sans droits administrateur, mais certains contrôles (BitLocker, exclusions Defender…) en ont besoin : ils sont alors marqués « non vérifié » et exclus du score.

## Utilisation (prévue)

```
aplomb.exe                                   # lance l'audit et ouvre le rapport
aplomb.exe --out D:\rapports --format html,md,json --lang fr --profile serveur
aplomb.exe help
```

Compatibilité visée : Windows 10/11 et Windows Server 2016+ (x64 ; ARM64 en bonus).

## Compilation

Prérequis : [Go](https://go.dev/dl/) (version de `go.mod`). Aucun CGO : la cross-compilation vers Windows fonctionne depuis Linux ou macOS.

```sh
make test        # tests
make windows     # dist/aplomb-windows-amd64.exe
make build-all   # tous les binaires Windows
make all         # format, vet, tests et binaires
```

## Licence

[GPL-3.0](LICENSE).
