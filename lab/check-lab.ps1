<#
.SYNOPSIS
    Compare un rapport JSON d'Aplomb aux faiblesses créées par make-vulnerable.ps1.
.PARAMETER Report
    Rapport JSON produit après make-vulnerable.ps1.
.PARAMETER Baseline
    Rapport JSON produit avant (facultatif) : ses défauts sont listés pour la
    chasse aux faux positifs d'une machine « neuve ».
#>
param([Parameter(Mandatory = $true)][string]$Report, [string]$Baseline)

function Load([string]$p) { Get-Content -LiteralPath $p -Raw -Encoding UTF8 | ConvertFrom-Json }

# Règle → objet attendu dans les constats (vide : la machine elle-même).
$expected = [ordered]@{
    'SVC-001' = 'AplombLabUnquoted'
    'SVC-002' = 'AplombLabWeakBin'
    'SVC-003' = 'AplombLabWeakKey'
    'TSK-001' = 'AplombLabWritable'
    'TSK-003' = 'AplombLabEncoded'
    'TSK-004' = 'AplombLabEncoded'
    'TSK-005' = 'AplombLabOrphan'
    'ACC-001' = ''
    'ACC-002' = ''
    'ACC-005' = ''
    'ACC-008' = 'aplomblab'
    'SMB-001' = 'AplombLabPublic'
    'SMB-005' = ''
    'SMB-006' = ''
    'FW-003'  = 'Aplomb Lab - Tout autoriser'
    'FW-004'  = 'Aplomb Lab - RDP public'
    'SYS-002' = ''
    'SYS-006' = ''
}
# Contrôles qui dépendent de la présence de Defender sur la machine.
$optional = @{ 'DEF-004' = 'C:\Users' }

$r = Load $Report
$byRule = @{}
foreach ($c in $r.checks) { $byRule[$c.rule] = $c }
$failed = 0
foreach ($id in $expected.Keys) {
    $c = $byRule[$id]
    $obj = $expected[$id]
    $ok = $c -and $c.status -eq 'fail'
    if ($ok -and $obj) { $ok = @($c.findings | Where-Object { $_.object -like "*$obj*" }).Count -gt 0 }
    if ($ok) { Write-Host ("OK      {0,-8} {1}" -f $id, $obj) -ForegroundColor Green }
    else {
        $failed++
        $st = if ($c) { "$($c.status) $($c.reason) $($c.reason_detail)" } else { 'absent' }
        Write-Host ("MANQUÉ  {0,-8} {1} → {2}" -f $id, $obj, $st) -ForegroundColor Red
    }
}
foreach ($id in $optional.Keys) {
    $c = $byRule[$id]
    $st = if ($c) { $c.status } else { 'absent' }
    Write-Host ("(info)  {0,-8} {1}" -f $id, $st)
}
Write-Host ("Score après dégradation : {0}/100, note {1}, couverture {2} %" -f $r.score.score, $r.score.grade, $r.score.coverage)

if ($Baseline) {
    $b = Load $Baseline
    Write-Host ''
    Write-Host ("Machine neuve : score {0}/100, note {1}, couverture {2} %" -f $b.score.score, $b.score.grade, $b.score.coverage)
    Write-Host 'Défauts relevés AVANT dégradation (à examiner : faux positifs ?) :'
    foreach ($c in ($b.checks | Where-Object { $_.status -eq 'fail' })) {
        $objs = ($c.findings | ForEach-Object { $_.object } | Where-Object { $_ }) -join ' ; '
        Write-Host ("  {0,-8} {1,-8} {2}" -f $c.rule, $c.level, $objs)
    }
    Write-Host 'Contrôles non vérifiés :'
    foreach ($c in ($b.checks | Where-Object { $_.status -eq 'not_checked' })) {
        Write-Host ("  {0,-8} {1} {2}" -f $c.rule, $c.reason, $c.reason_detail)
    }
}
if ($failed -gt 0) { Write-Host "$failed faiblesse(s) non détectée(s)" -ForegroundColor Red; exit 1 }
