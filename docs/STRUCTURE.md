# Aplomb — Analyseur d'hygiène et de sécurité Windows (Local Hardening Audit) — Structure projet

> Fichier de cadrage et de suivi d'implémentation. Il consigne tous les choix du projet et sert de référence à Claude Code pendant le développement sur la devbox Oracle.
> Statut : **étapes 0-7 terminées** — en cours : étape 8 (SMB).
> Nom : **Aplomb** — licence **GPL-3.0** — dépôt GitHub public — projet **séparé** d'Arpent.

---

## 1. Concept

Un **exécutable portable unique**, sans installation, qu'on lance sur un poste ou un serveur Windows pour vérifier en quelques secondes ses **failles de configuration locales** :

1. il inspecte la configuration de la machine (services, tâches planifiées, comptes et mots de passe, BitLocker, Defender, partages SMB, pare-feu…) ;
2. il évalue chaque point selon des **règles d'audit** (Info / Attention / Critique) ;
3. il calcule un **score de conformité** global et par catégorie ;
4. il génère un **rapport autonome HTML + Markdown** avec, pour chaque problème, une explication simple et la **commande PowerShell de remédiation**.

Cas d'usage visé : le même technicien/MSP qu'Arpent. Arpent audite **le réseau** depuis l'extérieur des machines ; cet outil audite **l'intérieur d'une machine**. Les deux ensemble couvrent un audit de PME complet.

**Hors périmètre** : agent permanent, supervision continue, EDR, antivirus, exploitation des failles trouvées. **L'outil est en lecture seule** : il ne modifie rien sur la machine auditée (§ 5.4).

---

## 2. Contraintes structurantes

| Contrainte | Conséquence |
|---|---|
| Un seul fichier, portable, rien à installer | Pas de module PowerShell à importer, pas de runtime .NET/Python à installer |
| Cible : **Windows 10/11 et Windows Server 2016+** (x64) | Build `windows/amd64` uniquement ; `windows/arm64` en bonus |
| Fonctionne **sans droits admin**, mais **mieux avec** | Mode dégradé explicite : les contrôles impossibles sans admin sont marqués « non vérifié » et ne comptent pas dans le score |
| Lecture seule | Aucune écriture dans le registre, les services ou la stratégie ; le rapport s'écrit à côté de l'exe |
| Développement sur la **devbox Oracle (Ubuntu 24.04, ARM64)** | Le langage doit cross-compiler vers Windows x64 ; les tests réels se font sur Windows (§ 9) |
| Budget 0 € | Briques libres uniquement |

---

## 3. Choix techniques (même socle qu'Arpent)

### Langage : Go
- Binaire unique statique, cross-compilation `GOOS=windows GOARCH=amd64` depuis la devbox.
- Accès natif aux API Windows sans PowerShell :
  - `golang.org/x/sys/windows` (+ `registry`, `svc/mgr`) : registre, services, ACL, jetons, droits ;
  - **WMI/CIM** via COM (`github.com/yusufpapurcu/wmi` / `go-ole`) : BitLocker (`Win32_EncryptableVolume`), Defender (`MSFT_MpComputerStatus`, `MSFT_MpPreference`), partages (`Win32_Share`), pare-feu (`MSFT_NetFirewallRule`), SMB (`MSFT_SmbServerConfiguration`) ;
  - API **Task Scheduler 2.0** (COM `Schedule.Service`) pour les tâches planifiées ;
  - API **NetAPI32** (`NetUserModalsGet`, `NetLocalGroupGetMembers`, `NetUserEnum`) pour la politique de mots de passe et les comptes.
- `embed` pour les règles, les traductions et les modèles de rapport.

### Pourquoi pas PowerShell en coulisse
- Plus lent, dépend de la politique d'exécution et du *Constrained Language Mode*, et un exe qui lance des dizaines de `powershell.exe` ressemble fortement à un malware pour les EDR.
- PowerShell n'apparaît **que dans le rapport**, comme commandes de remédiation à lancer par le technicien.

### Interface
- **v1 : CLI uniquement** — `aplomb.exe` sans argument lance l'audit et ouvre le rapport HTML dans le navigateur.
- `aplomb.exe --out D:\rapports --format html,md,json --lang fr --profile serveur`
- Pas de serveur web local en v1 (inutile pour un audit de quelques secondes) ; à reconsidérer si on fait un mode « comparaison » interactif.

---

## 4. Arborescence portable (à côté de l'exe)

```
aplomb.exe
aplomb-data/
├── config.yaml                    # technicien, société, logo, langue, profil par défaut, règles désactivées
└── rapports/
    └── PC-ACCUEIL-01/
        ├── 2026-11-25_1430.html   # rapport autonome (CSS inline)
        ├── 2026-11-25_1430.md
        └── 2026-11-25_1430.json   # résultats bruts (machine-readable, base pour la comparaison)
```

Un dossier par **nom de machine** : on lance l'exe depuis une clé USB sur 10 postes, on repart avec 10 rapports rangés.

---

## 5. Fonctionnalités

### 5.1 Contexte de la machine (en tête de rapport)
Nom, OS et build, date de la dernière mise à jour installée, rôle (poste / serveur membre / **contrôleur de domaine**), appartenance à un domaine ou Entra ID, utilisateur qui lance l'audit, **élévation admin oui/non**, matériel (TPM, Secure Boot, UEFI).

**Détection des GPO** : si un paramètre est imposé par stratégie de groupe, le rapport le dit et la remédiation proposée est « à corriger dans la GPO », pas en local (sinon la correction est écrasée au prochain `gpupdate`).

### 5.2 Catalogue des contrôles (v1)

**Services**
- *Unquoted Service Path* : chemin avec espaces, sans guillemets, hors `C:\Windows`, et un dossier intermédiaire inscriptible → Critique (sinon Attention).
- Binaire de service ou son dossier **modifiable par des non-admins** (ACL `Users`, `Authenticated Users`, `Everyone`) → Critique.
- Clé de registre du service modifiable par des non-admins → Critique.
- Services tiers tournant en `LocalSystem` depuis un dossier utilisateur/temp → Attention.
- Spouleur d'impression actif sur un contrôleur de domaine ou un serveur sans imprimante → Attention.

**Tâches planifiées**
- Tâche lancée en SYSTEM/admin dont l'exécutable ou le script est inscriptible par des non-admins → Critique.
- Action pointant vers `%TEMP%`, `AppData`, `Public`, `ProgramData` inscriptible → Attention.
- Ligne de commande suspecte : PowerShell `-EncodedCommand`/`-enc`, `-WindowStyle Hidden`, `mshta`, `rundll32` avec URL, `certutil -urlcache`, `bitsadmin` → Attention.
- Tâches masquées ou sans auteur, hors `\Microsoft\` → Info.
- Binaire introuvable (tâche orpheline) → Info.

**Comptes et mots de passe**
- Politique : longueur minimale < 12 (ou < 14 pour un serveur), pas de verrouillage de compte, durée max illimitée sans compensation, complexité désactivée.
- Compte Invité activé → Critique ; compte Administrateur intégré activé → Attention.
- Membres du groupe local Administrateurs (liste, et nombre anormal) → Info/Attention.
- Comptes locaux dont le mot de passe n'expire jamais ou n'est pas requis (`PASSWD_NOTREQD`) → Attention.
- **LAPS** (Windows LAPS ou legacy) absent sur une machine du domaine → Attention.

**Chiffrement — BitLocker**
- Volume système non chiffré → Critique (poste portable) / Attention (fixe, serveur).
- Chiffrement suspendu → Critique.
- Protecteur TPM seul sur un portable (pas de PIN) → Info.
- Clé de récupération non sauvegardée dans AD/Entra (si détectable) → Attention.
- Volumes de données non chiffrés → Attention.

**Microsoft Defender**
- Protection en temps réel désactivée → Critique.
- **Protection contre les falsifications** (Tamper Protection) désactivée → Attention.
- Signatures de plus de 7 jours → Attention.
- **Exclusions** larges (lecteur entier, `C:\Users`, `%TEMP%`, extensions `.exe`/`.ps1`) → Critique *(lecture des exclusions = admin requis)*.
- Protection cloud / envoi d'échantillons désactivés, PUA désactivé, règles ASR absentes → Info.
- Un autre antivirus actif → Defender passif normal, le rapport l'indique au lieu d'alerter.

**Partages SMB**
- Partages non administratifs accessibles à `Everyone`/`Utilisateurs` en écriture → Critique ; en lecture → Attention.
- **SMBv1** activé (serveur ou client) → Critique.
- Signature SMB non exigée → Attention (Critique sur un DC).
- Accès invité non sécurisé (`AllowInsecureGuestAuth`) → Attention.

**Pare-feu Windows**
- Un profil (Domaine/Privé/Public) désactivé → Critique.
- Action entrante par défaut « Autoriser » → Critique.
- Règles entrantes actives `Any` port + `Any` adresse distante → Attention.
- Ports sensibles ouverts à toute adresse sur le profil Public : RDP 3389, SMB 445, WinRM 5985/5986, bases de données → Attention.
- Règles autorisant un programme dans un dossier inscriptible → Attention.

**Durcissement système (bonus v1, faciles à lire dans le registre)**
- UAC désactivé ou réglé au minimum ; `AlwaysInstallElevated` → Critique.
- RDP actif sans NLA → Attention.
- LLMNR / NetBIOS sur TCP/IP activés → Attention.
- WDigest stockant les mots de passe en clair (`UseLogonCredential=1`) → Critique.
- Protection LSA (`RunAsPPL`) / Credential Guard désactivés → Info/Attention.
- PowerShell v2 installé ; journalisation PowerShell (Script Block Logging) désactivée → Info.
- Exécution automatique (AutoRun) des supports amovibles → Attention.
- Dernière mise à jour Windows de plus de 30/60 jours → Attention/Critique.
- Secure Boot désactivé → Attention.

### 5.3 Règles d'audit
- Chaque règle est déclarée dans un fichier embarqué (`rules.yaml`) : identifiant stable (`SVC-001`…), catégorie, niveau, profils concernés (poste / serveur / DC), poids dans le score, besoin d'admin, texte FR/EN (titre, explication simple pour le client, détail technique), **commande de remédiation**, références.
- **Règles maison**, pragmatiques pour des PME. **Pas de CIS** (ni contenu, ni identifiants, ni mention de conformité).
- **Références** citées par règle, à titre indicatif : Microsoft Security Baseline, recommandations ANSSI, techniques MITRE ATT&CK (on cite la source, on ne recopie pas son contenu).
- Désactivation de règles via `config.yaml` (avec justification qui apparaît dans le rapport : « risque accepté »).

### 5.4 Remédiation
- Pour chaque problème : une **commande PowerShell** prête à copier, avec un avertissement si elle a un impact (redémarrage, coupure de service, compatibilité — ex. désactiver SMBv1 peut casser un vieux copieur).
- Bouton « copier » dans le rapport HTML.
- **Script de remédiation** `.ps1` généré à part, regroupant toutes les corrections, **chaque bloc commenté par défaut** : le technicien décommente ce qu'il veut appliquer. Le script vérifie l'élévation, journalise ce qu'il fait et supporte `-WhatIf`.
- L'exe **n'applique jamais** lui-même une correction (v1). Garde l'outil simple, inoffensif et défendable.

### 5.5 Score de conformité
- Score sur **100**, global et par catégorie.
- Calcul : chaque règle applicable vaut un poids selon son niveau (ex. Critique 10, Attention 4, Info 1) ; score = poids des contrôles conformes / poids des contrôles vérifiés.
- Les contrôles **non vérifiés** (pas admin, fonctionnalité absente) sont exclus du calcul et listés à part, avec le **taux de couverture** (« 78 % des contrôles vérifiés — relancer en administrateur pour un audit complet »).
- Note lettre A → E pour le résumé non technique.
- **Plafond** : un seul Critique non corrigé plafonne la note à C (évite un 92/100 avec Defender désactivé).

### 5.6 Rapport
- **HTML autonome** (un seul fichier, CSS inline, lisible hors ligne, imprimable en PDF) :
  page de garde (machine, date, technicien, logo), jauge du score et note, résumé non technique, problèmes classés par gravité avec explication + remédiation, détail par catégorie, contrôles non vérifiés, annexe technique (valeurs brutes).
- **Markdown** : même contenu, pour un ticket, un wiki, Obsidian ou un dépôt Git.
- **JSON** : résultats bruts, schéma versionné.
- Langue du rapport choisie indépendamment de la langue de l'outil.

### 5.7 Cadre légal et éthique
- Outil de **contrôle de conformité en lecture seule** destiné à l'administrateur de la machine ou à un prestataire mandaté ; mention dans le README et dans le rapport.
- Le rapport contient des informations sensibles (comptes, chemins, faiblesses) : mention « confidentiel » et conseil de ne pas le laisser traîner sur la clé USB.

---

## 6. Modèle de données (JSON du rapport)

- `meta` : version de l'outil, version du schéma, date, durée, langue, profil, élévation
- `host` : nom, OS, build, rôle, domaine, matériel, dernière MAJ
- `checks[]` : id règle, catégorie, statut (`pass` / `fail` / `not_checked` / `not_applicable` / `accepted_risk`), niveau, preuve (valeurs observées), objet concerné (service, tâche, partage, règle…), remédiation
- `score` : global, par catégorie, couverture, note, plafond appliqué

Pas de base SQLite en v1 : un audit = un JSON. La comparaison (§ 11) lit deux JSON.

---

## 7. Architecture du code (Go)

```
cmd/aplomb/            # point d'entrée CLI
internal/host/          # contexte machine, élévation, rôle, domaine, GPO
internal/win/           # wrappers bas niveau : registre, WMI, COM, ACL, NetAPI, Task Scheduler
internal/checks/
    services/
    tasks/
    accounts/
    bitlocker/
    defender/
    smb/
    firewall/
    system/             # UAC, RDP, LLMNR, WDigest, LSA, MAJ…
internal/rules/         # chargement rules.yaml, évaluation, niveaux, profils
internal/score/
internal/report/        # rendu HTML, Markdown, JSON, script .ps1
internal/i18n/
assets/                 # rules.yaml, i18n/fr.json, en.json, templates, CSS
```

Chaque contrôle implémente la même interface : `Collect()` (lit l'état brut) puis évaluation par les règles. La collecte est séparée de l'évaluation pour pouvoir **tester les règles sur des jeux de données JSON enregistrés**, sans Windows.

---

## 8. Ce qui demande les droits admin

| Contrôle | Sans admin | Avec admin |
|---|---|---|
| Services, chemins, ACL des binaires | ✅ | ✅ |
| Tâches planifiées | ⚠️ partiel (pas celles des autres comptes) | ✅ |
| Politique de mots de passe, comptes locaux | ✅ | ✅ |
| BitLocker | ❌ | ✅ |
| Defender — état | ✅ | ✅ |
| Defender — exclusions | ❌ | ✅ |
| Partages SMB et leurs ACL | ⚠️ partiel | ✅ |
| Configuration serveur SMB | ⚠️ | ✅ |
| Pare-feu — profils et règles | ✅ | ✅ |
| Registre HKLM (UAC, LSA, WDigest…) | ✅ (lecture) | ✅ |

*Tableau à vérifier pendant l'implémentation et à tenir à jour.*

---

## 9. Développement et tests

- **Dev** sur la devbox Oracle, cross-compilation vers `windows/amd64`.
- **Tests unitaires** (sur la devbox) : règles, score, rendu du rapport, à partir de fichiers JSON de collecte enregistrés (« fixtures ») représentant des machines saines et volontairement mal configurées.
- **Tests d'intégration Windows** : GitHub Actions `windows-latest` (gratuit pour un dépôt public) — l'exe tourne réellement sur Windows Server à chaque commit.
- **Machine de test volontairement vulnérable** : VM Windows Server (version d'évaluation gratuite 180 jours) et/ou Windows 11 sur le Proxmox du homelab, avec un script `lab/make-vulnerable.ps1` qui crée un service à chemin sans guillemets, une tâche planifiée piégée, un partage `Everyone`, SMBv1, une exclusion Defender… Snapshot avant/après.
- Test final sur le PC Windows perso (cas réel).

---

## 10. Risques identifiés

| Risque | Parade |
|---|---|
| **Defender/EDR qui classent l'exe comme outil de reconnaissance** (les outils comme WinPEAS sont détectés) | Lecture seule, API natives plutôt que PowerShell, pas de chaînes « offensives », binaire signé (SignPath, comme Arpent), soumission faux positif à Microsoft |
| Faux positifs qui décrédibilisent le rapport (ex. chemin non cité mais pas exploitable) | Vérifier l'exploitabilité réelle (ACL du dossier) avant de passer en Critique ; niveaux nuancés |
| Remédiation qui casse quelque chose chez le client | Lecture seule, avertissements d'impact, script commenté par défaut, `-WhatIf` |
| Différences entre versions de Windows (Home sans BitLocker complet, Server Core, LTSC) | Statut `not_applicable` ; matrice de tests sur plusieurs versions |
| Machine gérée par GPO/Intune | Détection et remédiation « à faire dans la GPO/Intune » |
| Concurrence gratuite : HardeningKitty, PrivescCheck, CIS-CAT Lite, Microsoft Policy Analyzer | Se différencier par : exe portable sans PowerShell, rapport client en français avec score et résumé non technique, remédiation prête à l'emploi, complémentarité avec Arpent |

---

## 11. Fonctionnalités avancées (après la v1)

- **Comparaison** de deux rapports JSON d'une même machine : problèmes corrigés, nouveaux, régression du score.
- **Rapport consolidé multi-postes** : on agrège les JSON de 10 machines → tableau de bord du parc (pire machine, problème le plus répandu).
- **Profils d'exigence** : « Base », « Renforcé », « Serveur exposé ».
- **Lien avec Arpent** : import des rapports machine dans le site Arpent correspondant, pour un audit PME unique (réseau + postes).
- **Contrôles Active Directory légers** depuis un DC (sans concurrencer PingCastle).
- **Signature de code** via SignPath Foundation.
- Rapports à la marque (logo, couleurs, modèles surchargeables), comme Arpent.

---

## 12. Étapes d'implémentation (suivi pour Claude Code)

- [x] **Étape 0 — Socle** : dépôt, module Go, licence, README FR/EN, i18n, `Makefile`, GitHub Actions (tests Linux + exécution sur `windows-latest`), binaire « hello » sur Windows.
- [x] **Étape 1 — Contexte machine** : OS, rôle, domaine, élévation, matériel, dernière MAJ → JSON.
- [x] **Étape 2 — Moteur** : format `rules.yaml`, statuts, profils, score, fixtures de test.
- [x] **Étape 3 — Rapport v0** : HTML + Markdown + JSON à partir des résultats, ouverture automatique.
- [x] **Étape 4 — Services** : énumération, unquoted paths, ACL binaires/dossiers/clés.
- [x] **Étape 5 — Tâches planifiées.**
- [x] **Étape 6 — Comptes et politique de mots de passe**, LAPS.
- [x] **Étape 7 — BitLocker et Defender.**
- [ ] **Étape 8 — SMB et partages.**
- [ ] **Étape 9 — Pare-feu.**
- [ ] **Étape 10 — Durcissement système** (UAC, RDP, LLMNR, WDigest, LSA…).
- [ ] **Étape 11 — Remédiation** : commandes par règle, script `.ps1` commenté avec `-WhatIf`, détection GPO.
- [ ] **Étape 12 — Lab** : `make-vulnerable.ps1`, VM de test, chasse aux faux positifs.
- [ ] **Étape 13 — Finitions v1.0** : config, mode dégradé sans admin, textes FR/EN relus, publication GitHub Releases.

Chaque étape se termine par un exe Windows testable.

---

## 13. Décisions et questions ouvertes

- [x] **Projet séparé** d'Arpent : exe distinct, même stack et même style de rapport, passerelle prévue (§ 11).
- [x] **Remédiation : lecture seule** + commandes PowerShell dans le rapport + script `.ps1` commenté avec `-WhatIf`. L'exe ne modifie jamais la machine.
- [x] **Périmètre v1 : catalogue complet** du § 5.2 (6 catégories de départ + durcissement système).
- [x] **Pas de CIS.** Règles maison, références indicatives Microsoft Security Baseline / ANSSI / MITRE ATT&CK. Raison : licence CIS (CC BY-NC-SA 4.0) incompatible avec la GPL-3.0, les audits payants et SignPath.
- [x] **Stack : Go**, API Windows natives (registre, WMI/COM, NetAPI, Task Scheduler), pas de PowerShell en coulisse, **CLI seule en v1**.
- [x] **Licence : GPL-3.0**, comme Arpent ; dépôt GitHub public, binaires dans les GitHub Releases avec sommes SHA-256.
- [x] **Langues : français + anglais dès le départ**, via fichiers de traduction embarqués ; langue du rapport choisie séparément de celle de l'outil.

- [x] **Nom : Aplomb** — le fil à plomb vérifie qu'un mur est droit ; une machine « d'aplomb » est stable et bien réglée ; le mot existe aussi en anglais. Forme une paire avec Arpent (l'arpenteur mesure le terrain, le fil à plomb vérifie chaque mur). Binaire `aplomb` / `aplomb.exe`, module Go `github.com/maxb1906/aplomb`.
- [x] Vérifier que le dépôt `aplomb` est libre au moment de le créer (étape 0) : `maxb1906/aplomb` libre le 2026-11-25. Nom de domaine : non vérifié, pas nécessaire pour la v1.

---

## Journal des décisions

- **2026-11-25** — Projet lancé. Concept : exe portable Windows qui audite la configuration locale (services, tâches, mots de passe, BitLocker, Defender, SMB, pare-feu), score de conformité, rapport HTML/Markdown autonome avec commandes PowerShell de remédiation. Premier jet de cadrage rédigé, choix techniques proposés sur le modèle d'Arpent.
- **2026-11-25** — Projet **séparé** d'Arpent. Remédiation en **lecture seule** + script `.ps1` commenté. v1 avec le **catalogue complet**. Souhait d'un **alignement strict CIS** → problème de licence CIS (CC BY-NC-SA 4.0) identifié.
- **2026-11-25** — **CIS abandonné** : règles maison, références indicatives Microsoft / ANSSI / MITRE ATT&CK. Pistes de nom proposées.
- **2026-11-25** — Nom retenu : **Aplomb**.
- **2026-11-25** — Stack Go (API natives, CLI v1), licence GPL-3.0, FR + EN validés. **Cadrage terminé.**
- **2026-11-25** — **Étape 0 (socle)** : module `github.com/maxb1906/aplomb` (Go 1.27.4, aucune dépendance externe pour l'instant), licence GPL-3.0, README FR/EN, `CLAUDE.md`, package `internal/i18n` repris d'Arpent (variable `APLOMB_LANG`, test de complétude FR/EN), `Makefile` (`windows/amd64` + `windows/arm64`, `CGO_ENABLED=0`, `go vet` aussi en `GOOS=windows`), GitHub Actions (tests Ubuntu + `windows-latest`, cross-compilation avec SHA-256, lancement de l'exe sur `windows-latest`). CLI : `hello`, `version`, `help` ; **sans argument, l'exe affiche `hello` en attendant l'audit (étape 3)**. Lancé par double-clic, l'exe attend « Entrée » avant de fermer la console (repris d'Arpent, mais à chaque sortie et pas seulement en cas d'erreur). Pas de GoReleaser ni de workflow de release à ce stade (étape 13).
- **2026-11-25** — **Étape 1 (contexte machine)** : `internal/model` (snapshot JSON versionné, valeurs tri-états, `Gaps` pour expliquer une donnée manquante : `requires_admin` / `error` / `absent`), `internal/win` (registre en lecture seule, vue 64 bits, lecture « stratégie puis local » pour la détection GPO ; COM/WMI via `go-ole` + `yusufpapurcu/wmi`), `internal/host`. Sources : registre `CurrentVersion` (nom corrigé en « Windows 11 » si build ≥ 22000), `ProductType` → rôle, `NetGetJoinInformation`, clé `CloudDomainJoin` (Entra ID), jeton du processus (élévation), `GetFirmwareType`, `UEFISecureBootEnabled`, **TPM via TBS `Tbsi_GetDeviceInfo` (sans admin, contrairement à `Win32_Tpm`)**, châssis SMBIOS (+ batterie) → portable, `Win32_QuickFixEngineering` → dernière MAJ (date `InstalledOn`, peu fiable sur certains correctifs : limite connue). Commande `aplomb host` (JSON). Dépendances ajoutées : `golang.org/x/sys` v0.50.0, `go-ole` v1.3.0, `yusufpapurcu/wmi` v1.2.4, `yaml.v3`.
- **2026-11-25** — **Étape 2 (moteur)** : `assets/rules.yaml` = métadonnées + textes FR/EN (titre, résumé client, détail technique, impact, emplacement GPO) + modèle PowerShell de remédiation (`text/template`, fonction `ps` pour citer une valeur) ; **la logique de chaque règle est une fonction Go** enregistrée sous le même identifiant (`rules.Register`) dans `internal/checks/<catégorie>` — un YAML purement déclaratif ne pouvait pas exprimer les contrôles (ACL, chemins…). Validation au chargement (catégorie, niveau, profils, textes FR et EN, modèle) et test « chaque règle a sa logique et inversement ». Un constat peut préciser son niveau (ex. Critique seulement si le dossier est réellement inscriptible). Règle désactivée dans la config → `accepted_risk` avec justification si elle est en défaut. Score : poids 10/4/1, non vérifiés / non applicables / acceptés exclus, couverture en %, note A ≥ 90, B ≥ 75, C ≥ 60, D ≥ 40, E ; **plafond : un Critique en défaut ramène le score à 74 au plus (note C), le score brut reste dans le JSON**. Fixtures dans `testdata/snapshots/` (poste sain, poste vulnérable, serveur sans admin, DC). Premières règles : SYS-012 (mises à jour), SYS-013 (Secure Boot). Commande `aplomb rules`.
- **2026-11-25** — **Étape 3 (rapport v0)** : `internal/report` — HTML autonome (CSS et script en ligne, aucune ressource externe ; jauge SVG, note, résumé non technique rédigé à partir du score, problèmes classés par gravité, risques acceptés, non vérifiés, détail par catégorie, annexe technique repliable, bouton « Copier » avec repli hors contexte sécurisé `file://`, mise en page d'impression), Markdown (même contenu) et JSON (`meta`, `host`, `checks`, `score` + **`collection` = snapshot brut**, pour pouvoir réévaluer un rapport et, plus tard, comparer). Fichiers : `aplomb-data/rapports/<MACHINE>/AAAA-MM-JJ_HHMM.{html,md,json}` (+ `_remediation.ps1`), écriture atomique, ouverture par `ShellExecute`. **Sans argument, l'exe lance désormais `audit`.** Commandes ajoutées : `audit`, `collect` (snapshot brut → JSON, pour créer des fixtures à partir de vraies machines), `evaluate --input` (rejoue un snapshot ou un rapport, utilisable sur la devbox). **`config.yaml` avancé de l'étape 13** (technicien, société, logo encodé en `data:`, langues, profil, formats, règles désactivées) car le rapport en a besoin ; un modèle commenté est créé au premier audit.
- **2026-11-25** — **Étape 4 (services)** : configuration lue dans le registre (`Services\\*`, types Win32 uniquement, lisible sans admin) + état via `EnumServicesStatusEx` avec `SC_MANAGER_ENUMERATE_SERVICE` (et non `mgr.Connect`, qui demande tous les droits et échoue sans admin). Analyse des ACL (`internal/win`) : DACL via `GetNamedSecurityInfo`, ACE héritées seulement (inherit-only) ignorées, refus appliqués, groupes « non administrateurs » = Tout le monde, Utilisateurs, Utilisateurs authentifiés, INTERACTIF, Invités, ANONYMOUS, RÉSEAU, Utilisateurs avec pouvoir, Utilisateurs/Invités du domaine ; cache par chemin. Règles SVC-001 à SVC-005. **Nuances anti-faux positifs** : services désactivés ignorés (sauf clé de registre modifiable, qui permet de les réactiver) ; chemin sans guillemets = Critique seulement si un dossier intermédiaire est réellement inscriptible ; SVC-002 = Critique si le binaire est modifiable ou remplaçable (`delete_child`), **Attention si l'on peut seulement ajouter un fichier dans le dossier** (cas fréquent sous `ProgramData`) ; imprimantes virtuelles Microsoft ignorées pour le spouleur.
- **2026-11-25** — **Étape 5 (tâches planifiées)** : COM `Schedule.Service` (parcours récursif des dossiers, tâches masquées incluses), principal converti en SID pour ne pas dépendre de la langue (« AUTORITE NT\\Système »). Tâche « privilégiée » = SYSTEM, LocalService, NetworkService, groupe Administrateurs, RID 500 ou « exécuter avec les privilèges les plus élevés ». Résolution des exécutables sans chemin (System32…), détection du script lancé par un interpréteur (`-File`, extension). Règles TSK-001 à TSK-005. Choix anti-bruit : **TSK-001/TSK-002 ne portent que sur les tâches privilégiées et actives** (les tâches d'un utilisateur dans son AppData, comme OneDrive, ne permettent pas d'élévation) ; ProgramData n'est signalé que s'il est inscriptible ; détecteur de commandes suspectes testé contre des faux positifs (`-ep bypass`, `-File`, rundll32 système, certutil -store). Sans admin : résultat « conforme » accompagné de la mention « vérification partielle ».
- **2026-11-25** — **Étape 6 (comptes)** : politique via `NetUserModalsGet` (niveaux 0 et 3), **complexité via l'API SAM** (`samlib.dll` : `SamConnect` → `SamLookupDomainInSamServer`, avec repli sur `SamEnumerateDomainsInSamServer` pour un DC → `SamQueryInformationDomain`), comme `net accounts`, sans `secedit` ni admin. Comptes via `NetUserEnum` niveau 20 (RID → Invité/Administrateur sans dépendre de la langue ; sur un DC, seuls les RID 500/501 sont gardés), Administrateurs via `NetLocalGroupGetMembers` sur le SID S-1-5-32-544 (nom localisé résolu). LAPS : Windows LAPS (Intune, GPO ou config locale, `BackupDirectory`) ou ancienne LAPS (stratégie + extension installée). Règles ACC-001 à ACC-010. **Écarts / précisions** : seuils de longueur 12 (poste) / 14 (serveur, DC) ; **une longueur ≥ 14 compense l'absence d'expiration (ACC-003, ACC-009) et de complexité (ACC-004)**, conformément aux recommandations actuelles qui privilégient la longueur ; « nombre anormal » d'administrateurs = plus de 3 membres hors comptes intégrés (RID 500, 512, 519, rôles Entra) ; sur une machine du domaine, la politique de mots de passe est marquée « à corriger dans la GPO » ; la remédiation LAPS reprend l'OU de la machine (`Distinguished-Name` de l'état des stratégies).
- **2026-11-25** — **Étape 7 (BitLocker et Defender)** : WMI par COM direct (`SWbemLocator`), nécessaire pour appeler les méthodes `GetKeyProtectors` / `GetKeyProtectorType` de `Win32_EncryptableVolume` (la bibliothèque `wmi` ne lit que les propriétés). BitLocker : BDE-001 à BDE-006 ; « sauvegarde de la clé dans AD/Entra » n'est pas vérifiable depuis la machine → **séparé en BDE-004 (Attention : aucun mot de passe de récupération) et BDE-006 (Info : sauvegarde non imposée par stratégie, à contrôler dans l'annuaire)** ; volumes sans lettre (EFI, récupération) et amovibles ignorés ; espace de noms absent (Windows Famille, serveur sans la fonctionnalité) → non applicable. Defender : `MSFT_MpComputerStatus` / `MSFT_MpPreference`, **exclusions imposées par GPO lues dans `HKLM\\SOFTWARE\\Policies` (visibles sans admin)**, antivirus tiers via `SecurityCenter2` (postes uniquement, décodage de `productState`) ; autre antivirus actif ou mode passif → toutes les règles DEF non applicables avec mention. DEF-001 à DEF-007 ; **DEF-002 (falsifications) limitée aux postes** : sur serveur, la fonction dépend de l'intégration à Defender for Endpoint.
