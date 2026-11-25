# Laboratoire Aplomb

Scripts pour valider Aplomb sur une machine **volontairement vulnérable**. À n'utiliser que sur une machine de test jetable : VM Windows Server (évaluation gratuite 180 jours) ou Windows 11 sur le Proxmox du homelab, ou runner de CI.

| Script | Rôle |
|---|---|
| `make-vulnerable.ps1 -ConfirmLab` | Crée les faiblesses (services, tâches, partage, comptes, SMB, pare-feu, WDigest, AlwaysInstallElevated, exclusions Defender). |
| `undo-vulnerable.ps1 -ConfirmLab` | Les annule (restaurer le snapshot reste préférable). |
| `check-lab.ps1 -Report après.json [-Baseline avant.json]` | Vérifie que chaque faiblesse est détectée et liste les défauts d'une machine neuve (chasse aux faux positifs). |

## Procédure sur une VM

1. Installer Windows (Server 2016/2019/2022/2025, Windows 10/11), à jour, **sans** la joindre au domaine de production.
2. **Snapshot « neuf »**.
3. Copier `aplomb.exe` et le dossier `lab\` sur la VM, ouvrir PowerShell **en administrateur** :
   ```powershell
   .\aplomb.exe audit --no-open --out C:\lab-reports\avant
   .\lab\make-vulnerable.ps1 -ConfirmLab
   .\aplomb.exe audit --no-open --out C:\lab-reports\apres
   .\lab\check-lab.ps1 -Report (Get-ChildItem C:\lab-reports\apres -Recurse -Filter *.json).FullName `
                       -Baseline (Get-ChildItem C:\lab-reports\avant -Recurse -Filter *.json).FullName
   ```
4. Refaire l'audit **sans** droits administrateur (console normale) pour vérifier le mode dégradé : les contrôles BitLocker, exclusions Defender, ACL des partages… doivent apparaître « non vérifiés », pas « conformes ».
5. Examiner les défauts de la machine neuve : chacun doit être justifié (faiblesse réelle d'une installation par défaut) ou corrigé dans Aplomb (faux positif).
6. Restaurer le snapshot.

Pour enrichir les fixtures de test, `aplomb.exe collect --out machine.json` enregistre le snapshot brut d'une machine réelle ; une fois anonymisé (noms de machine, de comptes, de domaine), il peut rejoindre `testdata/snapshots/`.

## En CI

Le job « Lab » de `.github/workflows/ci.yml` fait la même chose sur `windows-latest` (Windows Server, administrateur) : audit avant, dégradation, audit après, `check-lab.ps1`. Le rapport HTML est conservé comme artefact.
