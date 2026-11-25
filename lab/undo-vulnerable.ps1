<#
.SYNOPSIS
    Annule les modifications de lab/make-vulnerable.ps1.
.DESCRIPTION
    Rétablit des valeurs sûres (politique de mots de passe : longueur 14,
    verrouillage après 10 essais ; signature SMB exigée…). Sur une VM, restaurer
    le snapshot reste la méthode la plus sûre.
#>
[CmdletBinding()]
param([switch]$ConfirmLab)

$ErrorActionPreference = 'Continue'
if (-not $ConfirmLab) { throw 'Relancez avec -ConfirmLab.' }

function Step([string]$label, [scriptblock]$block) {
    try { & $block; Write-Host "[undo] $label" } catch { Write-Warning "[undo] $label : $_" }
}

Step 'services' { foreach ($s in 'AplombLabUnquoted', 'AplombLabWeakBin', 'AplombLabWeakKey') { & sc.exe delete $s | Out-Null } }
Step 'tâches' { Get-ScheduledTask -TaskPath '\AplombLab\' -ErrorAction SilentlyContinue | Unregister-ScheduledTask -Confirm:$false }
Step 'partage' { Remove-SmbShare -Name 'AplombLabPublic' -Force -ErrorAction SilentlyContinue }
Step 'fichiers' { Remove-Item -Recurse -Force 'C:\AplombLab', 'C:\Aplomb Lab' -ErrorAction SilentlyContinue }
Step 'comptes' {
    & net.exe accounts /minpwlen:14 /lockoutthreshold:10 /lockoutwindow:15 /lockoutduration:15 | Out-Null
    Get-LocalUser | Where-Object { $_.SID.Value -like '*-501' } | Disable-LocalUser
    & net.exe user aplomblab /delete | Out-Null
}
Step 'SMB' {
    Set-SmbServerConfiguration -RequireSecuritySignature $true -Force
    Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' -Name AllowInsecureGuestAuth -Value 0 -Type DWord
}
Step 'pare-feu' { Get-NetFirewallRule -DisplayName 'Aplomb Lab - *' -ErrorAction SilentlyContinue | Remove-NetFirewallRule }
Step 'AlwaysInstallElevated' {
    foreach ($h in 'HKLM:', 'HKCU:') {
        Remove-ItemProperty -Path "$h\SOFTWARE\Policies\Microsoft\Windows\Installer" -Name AlwaysInstallElevated -ErrorAction SilentlyContinue
    }
}
Step 'WDigest' { Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -Name UseLogonCredential -Value 0 -Type DWord }
Step 'Defender' {
    if (Get-Command Remove-MpPreference -ErrorAction SilentlyContinue) {
        Remove-MpPreference -ExclusionPath 'C:\Users' -ExclusionExtension 'exe'
    }
}
