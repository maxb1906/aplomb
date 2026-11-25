# Aplomb

[Français](README.md) · **English**

[![CI](https://github.com/maxb1906/aplomb/actions/workflows/ci.yml/badge.svg)](https://github.com/maxb1906/aplomb/actions/workflows/ci.yml)
[![License: GPL-3.0](https://img.shields.io/badge/license-GPL--3.0-blue.svg)](LICENSE)

A **portable** tool that audits the security configuration of a **Windows** workstation or server. A single executable, no installation: run it on the machine, it checks its local configuration weaknesses in a few seconds and produces a **report** with a compliance score and, for each issue, a plain-language explanation and the PowerShell command to fix it.

Built for technicians, freelancers and MSPs working with small businesses. A companion to [Arpent](https://github.com/maxb1906/arpent): Arpent audits the network, Aplomb audits the inside of each machine.

> 🚧 **Work in progress** — nothing usable yet. Progress is tracked (in French) in [docs/STRUCTURE.md](docs/STRUCTURE.md).

## What Aplomb will check (v1)

- **Services**: exploitable unquoted paths; binaries, folders and registry keys writable by non-administrators.
- **Scheduled tasks**: SYSTEM tasks pointing to writable files, suspicious command lines, orphaned tasks.
- **Accounts and passwords**: password and lockout policy, Guest and built-in Administrator accounts, Administrators group members, LAPS.
- **BitLocker**: unencrypted or suspended volumes, protectors.
- **Microsoft Defender**: real-time protection, tamper protection, signature age, overly broad exclusions.
- **SMB shares**: shares open to everyone, SMBv1, SMB signing, guest access.
- **Windows Firewall**: disabled profiles, overly permissive inbound rules, exposed sensitive ports.
- **System hardening**: UAC, RDP without NLA, LLMNR/NetBIOS, WDigest, LSA protection, updates, Secure Boot…

Self-contained HTML, Markdown and JSON report, in **French or English**, with a `.ps1` remediation script whose blocks are all commented out by default.

## ⚖️ Read-only, and intended use

Aplomb is a **read-only compliance checking tool**: it **never changes** the audited machine and exploits nothing. It is meant for the machine's administrator or a provider mandated by its owner.

The report contains sensitive information (accounts, paths, weaknesses): treat it as **confidential** and do not leave it lying around on a USB stick.

Aplomb works without administrator rights, but some checks (BitLocker, Defender exclusions…) need them: they are then marked "not checked" and excluded from the score.

## Usage (planned)

```
aplomb.exe                                   # runs the audit and opens the report
aplomb.exe --out D:\reports --format html,md,json --lang en --profile serveur
aplomb.exe help
```

Target platforms: Windows 10/11 and Windows Server 2016+ (x64; ARM64 as a bonus).

## Building

Requirements: [Go](https://go.dev/dl/) (version from `go.mod`). No CGO: cross-compiling to Windows works from Linux or macOS.

```sh
make test        # tests
make windows     # dist/aplomb-windows-amd64.exe
make build-all   # all Windows binaries
make all         # format, vet, tests and binaries
```

## License

[GPL-3.0](LICENSE).
