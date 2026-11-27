# Aplomb

[Français](README.md) · **English**

[![CI](https://github.com/maxb1906/aplomb/actions/workflows/ci.yml/badge.svg)](https://github.com/maxb1906/aplomb/actions/workflows/ci.yml)
[![License: GPL-3.0](https://img.shields.io/badge/license-GPL--3.0-blue.svg)](LICENSE)

A **portable** tool that audits the security configuration of a **Windows** workstation or server. A single executable, no installation and no PowerShell behind the scenes: run it on the machine, it checks its local configuration weaknesses in a few seconds and produces a **report** with a compliance score and, for each issue, a plain-language explanation and the PowerShell command to fix it.

Built for technicians, freelancers and MSPs working with small businesses. A companion to [Arpent](https://github.com/maxb1906/arpent): Arpent audits the network, Aplomb audits the inside of each machine.

## ⚖️ Read-only, and intended use

Aplomb is a **read-only compliance checking tool**: it **never changes** the audited machine and exploits nothing. It is meant for the machine's administrator or a provider mandated by its owner.

The report contains sensitive information (accounts, paths, weaknesses): treat it as **confidential** and do not leave it lying around on a USB stick.

## What Aplomb checks (57 rules)

| Category | Example checks |
|---|---|
| **System hardening** (13) | UAC, AlwaysInstallElevated, RDP without NLA, LLMNR, NetBIOS, WDigest, LSA protection, Credential Guard, PowerShell 2.0, PowerShell logging, AutoRun, updates, Secure Boot |
| **Services** (5) | exploitable unquoted paths, binaries/folders/registry keys writable by non-admins, SYSTEM service started from a user folder, needless spooler on server/DC |
| **Scheduled tasks** (5) | privileged task running a writable file, risky locations, suspicious commands (encoded PowerShell, mshta, certutil…), hidden and orphaned tasks |
| **Accounts and passwords** (10) | minimum length, lockout, expiration, complexity, Guest, built-in Administrator, Administrators group members, passwordless accounts, LAPS |
| **BitLocker** (6) | unencrypted system and data volumes, suspended protection, TPM-only on laptops, recovery password, enforced backup |
| **Microsoft Defender** (7) | real-time, tamper protection, signatures, overly broad exclusions, cloud, PUA, ASR rules |
| **SMB shares** (6) | shares open to everyone for write/read (share **and** NTFS permissions), SMBv1 server and client, signing, guest access |
| **Windows Firewall** (5) | disabled profiles, "Allow" inbound default, allow-all rules, sensitive ports open on the Public profile, writable programs |

`aplomb rules` lists every rule. They are defined in [assets/rules.yaml](assets/rules.yaml) (in-house rules; indicative references to Microsoft, ANSSI and MITRE ATT&CK).

Each rule applies according to the machine **profile** (workstation, member server, domain controller), detected automatically. Levels are **Info / Warning / Critical**, nuanced to avoid false positives (e.g. an unquoted path is only Critical if an intermediate folder is actually writable). When a setting is enforced by **GPO or Intune**, the report says so: fix it in the policy.

## Getting started

1. Download `aplomb_<version>_windows_amd64.zip` from the [Releases](https://github.com/maxb1906/aplomb/releases) and unzip it onto a USB stick.
2. Run `aplomb.exe`: the **graphical interface** opens. If you are not an administrator, the "Restart as administrator" button gives a complete audit. Click "Start the audit": it takes a few seconds.
3. Reports are stored next to the executable, one folder per machine (`aplomb-data/rapports/<MACHINE>/`; the window's cache goes to `aplomb-data/webview2/`): `.html` (self-contained, printable to PDF), `.md`, `.json` (raw results + collected data) and `_remediation.ps1` (all fixes commented out).

Without administrator rights, Aplomb runs in **degraded mode**: checks it cannot perform (BitLocker, Defender exclusions, share permissions, LSA protection…) are marked "not checked", excluded from the score, and the coverage rate is shown.

> **SmartScreen / antivirus**: the executable is not signed yet. Windows may show "Windows protected your PC": click "More info" then "Run anyway". Check the hash against the release's `SHA256SUMS` file.

## Graphical interface

Without arguments, `aplomb.exe` opens a window (Wails + WebView2):

- **Audit**: machine, elevation ("Restart as administrator" button), profile and report language, section-by-section progress;
- **Results**: score, grade and summary, issues sorted by severity with filters (level, category, search), details of each check, affected objects, ready-to-copy fix, checks not performed, per-category details; buttons to the HTML report, the remediation script and the folder;
- **Accept a risk** from an issue: the justification is saved in `config.yaml` and the report is regenerated;
- **History** of all reports in `aplomb-data` (several machines: one USB stick, ten workstations);
- **Settings**: technician, company, logo, languages, profile, formats, disabled rules.

The interface produces exactly the same files as the command line. It relies on the **Microsoft Edge WebView2** component, present on Windows 10/11 and Windows Server 2025; if it is missing (Windows Server 2016 to 2022 without Edge), Aplomb runs the audit **in the console**, like v1. `aplomb.exe audit` always forces the console.

## Score

Score out of 100, overall and per category: each checked control weighs 10 (Critical), 4 (Warning) or 1 (Info); score = weight of compliant checks / weight of checked controls. Grade A (≥ 90) to E (< 40). **A single Critical issue caps the grade at C** (score brought down to 74 at most; the raw score is in the report).

## Remediation

For each issue, the report gives a ready-to-copy PowerShell command and warns about its impact (restart, compatibility…). The `…_remediation.ps1` script gathers all fixes, **each one commented out**: uncomment the ones you choose, then run it as administrator on the audited machine (it refuses to run anywhere else). `-WhatIf` simulates, and everything is logged to a `.log` next to the script. Fixes for a GPO-enforced setting start with `##`: fix the policy instead.

## Command line

```
aplomb                                    # graphical interface (default; console if WebView2 is missing)
aplomb audit                              # console audit, then open the report
aplomb audit --out D:\reports --format html,md,json,ps1 --report-lang en --profile server --no-open
aplomb config --technician "Name" --company "My company" --logo logo.png
aplomb collect --out machine.json         # raw data, no evaluation
aplomb evaluate --input machine.json      # report from saved data (also on Linux/macOS)
aplomb rules | host | version | help      # aplomb <command> -h for options
```

Global options: `--lang fr|en` and `--data <folder>` (or the `APLOMB_DATA` variable).

## Configuration

`aplomb-data/config.yaml` (created at the first audit): technician, company and logo for the cover page, tool and report languages, forced profile, formats, and **disabled rules** — their failure then shows as "accepted risk" with the justification:

```yaml
disabled_rules:
  - id: SMB-003
    reason: "Old SMBv1 copier, replacement planned for 2027"
```

## Building and testing

Requirements: [Go](https://go.dev/dl/) (version from `go.mod`) and [Node.js](https://nodejs.org/) LTS for the graphical interface (`frontend/`, Svelte). No CGO: cross-compiling to Windows works from Linux or macOS.

```sh
make test        # tests (rules, score, reports on JSON fixtures)
make windows     # dist/aplomb-windows-amd64.exe (also builds the interface and the resources: icon, manifest)
make build-all   # windows/amd64 and windows/arm64
make all         # format, vet (Linux and Windows), tests, binaries
make mock && (cd frontend && npm run dev)   # interface in a browser, with demo data
```

CI also runs the exe on Windows Server (including opening the window), checks the syntax of the remediation scripts with PowerShell 5.1 and 7, and replays the [lab](lab/README.md): a machine made deliberately vulnerable must have every weakness detected. Releases are published by GoReleaser on each `vX.Y.Z` tag.

## License

[GPL-3.0](LICENSE).
