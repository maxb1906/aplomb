<#
.SYNOPSIS
    Vérifie la syntaxe des scripts de remédiation générés par Aplomb (CI).
.DESCRIPTION
    Pour chaque fichier *_remediation.ps1 sous -Path : analyse le script tel
    quel, puis une copie où tous les blocs Invoke-AplombFix sont décommentés,
    avec le parseur PowerShell. Aucune commande n'est exécutée.
#>
param([Parameter(Mandatory = $true)][string]$Path)

$files = Get-ChildItem -Path $Path -Recurse -Filter '*_remediation.ps1'
if (-not $files) { throw "Aucun script de remédiation sous $Path" }
$failed = 0
foreach ($f in $files) {
    $text = Get-Content -LiteralPath $f.FullName -Raw -Encoding UTF8
    $uncommented = ($text -split "`r`n" | ForEach-Object { $_ -replace '^#{1,2} (Invoke-AplombFix |    |\})', '$1' }) -join "`r`n"
    foreach ($variant in @(@{ Name = 'tel quel'; Text = $text }, @{ Name = 'décommenté'; Text = $uncommented })) {
        $tokens = $null; $errors = $null
        [void][System.Management.Automation.Language.Parser]::ParseInput($variant.Text, [ref]$tokens, [ref]$errors)
        if ($errors.Count -gt 0) {
            $failed++
            Write-Host "ÉCHEC $($f.Name) ($($variant.Name)) :" -ForegroundColor Red
            $errors | ForEach-Object { Write-Host ("  ligne {0} : {1}" -f $_.Extent.StartLineNumber, $_.Message) }
        }
    }
    $blocks = ([regex]::Matches($uncommented, '(?m)^Invoke-AplombFix ')).Count
    Write-Host ("OK {0} ({1} correction(s))" -f $f.Name, $blocks)
}
if ($failed -gt 0) { exit 1 }
