<#
.SYNOPSIS
    Rend une machine de TEST volontairement vulnérable pour valider Aplomb.
.DESCRIPTION
    À n'utiliser QUE sur une machine virtuelle de laboratoire jetable (snapshot
    avant/après) ou un runner de CI. Crée des faiblesses que chaque règle
    d'Aplomb doit détecter : service à chemin sans guillemets, binaire et clé de
    service modifiables, tâches planifiées piégées, partage ouvert à tous,
    signature SMB désactivée, comptes et politique de mots de passe faibles,
    règles de pare-feu trop larges, WDigest, AlwaysInstallElevated, exclusions
    Defender…

    Aucun programme malveillant n'est installé : les « programmes » sont des
    copies de where.exe, les tâches sont planifiées en 2099 et les services en
    démarrage manuel. lab/undo-vulnerable.ps1 annule ces modifications.
.PARAMETER ConfirmLab
    Obligatoire : confirme qu'il s'agit d'une machine de laboratoire.
.EXAMPLE
    .\make-vulnerable.ps1 -ConfirmLab
#>
[CmdletBinding()]
param([switch]$ConfirmLab)

$ErrorActionPreference = 'Stop'
if (-not $ConfirmLab) {
    throw 'Machine de laboratoire uniquement : relancez avec -ConfirmLab (après avoir pris un snapshot).'
}
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'À lancer en tant qu''administrateur.'
}

function Name-Of([string]$sid) { (New-Object Security.Principal.SecurityIdentifier $sid).Translate([Security.Principal.NTAccount]).Value }
$everyone = Name-Of 'S-1-1-0'
$users = Name-Of 'S-1-5-32-545'
$authUsers = Name-Of 'S-1-5-11'

function Step([string]$label, [scriptblock]$block) {
    $global:LASTEXITCODE = 0
    try {
        & $block
        if ($LASTEXITCODE -ne 0) { Write-Warning "[lab] $label : code de sortie $LASTEXITCODE" }
        else { Write-Host "[lab] $label" -ForegroundColor Yellow }
    } catch { Write-Warning "[lab] $label : $_" }
    $global:LASTEXITCODE = 0
}
function Grant([string]$path, [string]$who, [string]$rights) {
    $acl = Get-Acl -LiteralPath $path
    $inherit = if ((Get-Item -LiteralPath $path).PSIsContainer) { 'ContainerInherit,ObjectInherit' } else { 'None' }
    $rule = New-Object Security.AccessControl.FileSystemAccessRule($who, $rights, $inherit, 'None', 'Allow')
    $acl.AddAccessRule($rule)
    Set-Acl -LiteralPath $path -AclObject $acl
}

$root = 'C:\AplombLab'
$exe = Join-Path $env:SystemRoot 'System32\where.exe'
New-Item -ItemType Directory -Force -Path $root | Out-Null

# --- Services --------------------------------------------------------------
Step 'SVC-001 service à chemin sans guillemets, dossier intermédiaire inscriptible' {
    $dir = 'C:\Aplomb Lab\Vuln App'
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
    Copy-Item $exe (Join-Path $dir 'svc.exe') -Force
    Grant 'C:\Aplomb Lab' $users 'Modify'
    & sc.exe create AplombLabUnquoted binPath= "$dir\svc.exe" start= demand | Out-Null
}
Step 'SVC-002 binaire de service modifiable par Utilisateurs' {
    $dir = Join-Path $root 'weakbin'
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
    Copy-Item $exe (Join-Path $dir 'weak.exe') -Force
    Grant (Join-Path $dir 'weak.exe') $users 'Modify'
    & sc.exe create AplombLabWeakBin binPath= "$dir\weak.exe" start= demand | Out-Null
}
Step 'SVC-003 clé de service modifiable par Utilisateurs authentifiés' {
    $dir = Join-Path $root 'weakkey'
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
    Copy-Item $exe (Join-Path $dir 'k.exe') -Force
    & sc.exe create AplombLabWeakKey binPath= "$dir\k.exe" start= demand | Out-Null
    $k = 'HKLM:\SYSTEM\CurrentControlSet\Services\AplombLabWeakKey'
    $acl = Get-Acl -Path $k
    $acl.AddAccessRule((New-Object Security.AccessControl.RegistryAccessRule($authUsers, 'SetValue', 'Allow')))
    Set-Acl -Path $k -AclObject $acl
}

# --- Tâches planifiées -----------------------------------------------------
$trigger = New-ScheduledTaskTrigger -Once -At ([datetime]'2099-01-01T03:00:00')
Step 'TSK-001 tâche SYSTEM lançant un script modifiable' {
    $dir = Join-Path $root 'task'
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
    Set-Content -Path (Join-Path $dir 'job.ps1') -Value 'exit 0'
    Grant (Join-Path $dir 'job.ps1') $users 'Modify'
    $a = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -File `"$dir\job.ps1`""
    Register-ScheduledTask -TaskName 'AplombLabWritable' -TaskPath '\AplombLab\' -Action $a -Trigger $trigger -User 'SYSTEM' -Force | Out-Null
}
Step 'TSK-003/TSK-004 tâche masquée, sans auteur, commande encodée' {
    $enc = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes('exit 0'))
    $a = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -WindowStyle Hidden -EncodedCommand $enc"
    $s = New-ScheduledTaskSettingsSet -Hidden
    Register-ScheduledTask -TaskName 'AplombLabEncoded' -TaskPath '\AplombLab\' -Action $a -Trigger $trigger -Settings $s -User 'SYSTEM' -Force | Out-Null
}
Step 'TSK-005 tâche orpheline' {
    $a = New-ScheduledTaskAction -Execute (Join-Path $root 'missing\gone.exe')
    Register-ScheduledTask -TaskName 'AplombLabOrphan' -TaskPath '\AplombLab\' -Action $a -Trigger $trigger -User 'SYSTEM' -Force | Out-Null
}

# --- Comptes ---------------------------------------------------------------
Step 'ACC-001/ACC-002 politique de mots de passe faible' { & net.exe accounts /minpwlen:0 /lockoutthreshold:0 | Out-Null }
Step 'ACC-005 compte Invité activé' { Get-LocalUser | Where-Object { $_.SID.Value -like '*-501' } | Enable-LocalUser }
Step 'ACC-008 compte local sans mot de passe obligatoire' {
    & net.exe user aplomblab 'Lab-Aplomb-2026!' /add /passwordreq:no | Out-Null
}

# --- SMB -------------------------------------------------------------------
Step 'SMB-001 partage modifiable par tout le monde' {
    $dir = Join-Path $root 'share'
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
    Grant $dir $everyone 'Modify'
    New-SmbShare -Name 'AplombLabPublic' -Path $dir -FullAccess $everyone | Out-Null
}
Step 'SMB-005 signature SMB non exigée' { Set-SmbServerConfiguration -RequireSecuritySignature $false -Force }
Step 'SMB-006 connexions invité non sécurisées' {
    Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' -Name AllowInsecureGuestAuth -Value 1 -Type DWord
}

# --- Pare-feu --------------------------------------------------------------
Step 'FW-003 règle entrante tout port / toute adresse' {
    New-NetFirewallRule -DisplayName 'Aplomb Lab - Tout autoriser' -Direction Inbound -Action Allow -Protocol TCP -Profile Any | Out-Null
}
Step 'FW-004 RDP ouvert à tous sur le profil Public' {
    New-NetFirewallRule -DisplayName 'Aplomb Lab - RDP public' -Direction Inbound -Action Allow -Protocol TCP -LocalPort 3389 -Profile Public | Out-Null
}

# --- Durcissement système --------------------------------------------------
Step 'SYS-002 AlwaysInstallElevated (HKLM et HKCU)' {
    foreach ($h in 'HKLM:', 'HKCU:') {
        $k = "$h\SOFTWARE\Policies\Microsoft\Windows\Installer"
        if (-not (Test-Path $k)) { New-Item -Path $k -Force | Out-Null }
        Set-ItemProperty -Path $k -Name AlwaysInstallElevated -Value 1 -Type DWord
    }
}
Step 'SYS-006 WDigest en clair' {
    $k = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest'
    if (-not (Test-Path $k)) { New-Item -Path $k -Force | Out-Null }
    Set-ItemProperty -Path $k -Name UseLogonCredential -Value 1 -Type DWord
}

# --- Defender (si présent) -------------------------------------------------
Step 'DEF-004 exclusions Defender trop larges' {
    if (Get-Command Add-MpPreference -ErrorAction SilentlyContinue) {
        Add-MpPreference -ExclusionPath 'C:\Users' -ExclusionExtension 'exe'
    }
}

Write-Host 'Machine de laboratoire dégradée. Lancez Aplomb, puis lab\undo-vulnerable.ps1 -ConfirmLab ou restaurez le snapshot.' -ForegroundColor Cyan
exit 0
