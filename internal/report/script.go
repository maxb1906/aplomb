package report

import (
	"bufio"
	"io"
	"sort"
	"strings"

	"github.com/maxb1906/aplomb/internal/rules"
)

// Script écrit le script de remédiation PowerShell (§ 5.4) : toutes les
// corrections y sont COMMENTÉES ; le technicien décommente celles qu'il veut
// appliquer. Le script vérifie l'élévation et la machine, journalise
// (Start-Transcript) et prend en charge -WhatIf. Encodage UTF-8 avec BOM et fins
// de ligne CRLF, pour Windows PowerShell 5.1.
func Script(w io.Writer, r *Report, o Options) error {
	tr := o.Translator
	bw := bufio.NewWriter(w)
	lines := []string{}
	add := func(s ...string) { lines = append(lines, s...) }
	q := func(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }
	sep := "# " + strings.Repeat("-", 76)

	add("#Requires -Version 5.1",
		"<#",
		".SYNOPSIS",
		"    "+tr.T("script.synopsis", "host", r.Host.Name, "date", formatDateTime(r.Meta.CollectedAt, tr.Lang())),
		".DESCRIPTION",
		"    "+tr.T("script.desc1"),
		"    "+tr.T("script.desc2"),
		"    "+tr.T("script.desc3"),
		"    "+tr.T("script.desc4"),
		".EXAMPLE",
		"    .\\"+BaseName(r.Meta.CollectedAt)+"_remediation.ps1 -WhatIf",
		"#>",
		"[CmdletBinding(SupportsShouldProcess = $true)]",
		"param()",
		"",
		"Set-StrictMode -Version 2",
		"$ErrorActionPreference = 'Stop'",
		"",
		"if ($env:COMPUTERNAME -ne "+q(r.Host.Name)+") {",
		"    throw "+q(tr.T("script.wrong_host", "host", r.Host.Name)),
		"}",
		"$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())",
		"if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {",
		"    throw "+q(tr.T("script.need_admin")),
		"}",
		"",
		"$logDir = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }",
		"$log = Join-Path $logDir ('aplomb-remediation_' + (Get-Date -Format 'yyyy-MM-dd_HHmmss') + '.log')",
		"Start-Transcript -Path $log -Append | Out-Null",
		"",
		"function Invoke-AplombFix {",
		"    [CmdletBinding(SupportsShouldProcess = $true)]",
		"    param([string]$Id, [string]$Target, [scriptblock]$Fix)",
		"    if ($PSCmdlet.ShouldProcess($Target, $Id)) {",
		"        try {",
		"            & $Fix",
		"            Write-Host ('[OK] ' + $Id + ' ' + $Target) -ForegroundColor Green",
		"        } catch {",
		"            Write-Warning ('[ERREUR/ERROR] ' + $Id + ' ' + $Target + ' : ' + $_)",
		"        }",
		"    }",
		"}",
		"")

	// Constats en défaut, du plus grave au moins grave.
	var fails []rules.Result
	for _, res := range r.Checks {
		if res.Status == rules.Fail {
			fails = append(fails, res)
		}
	}
	sort.SliceStable(fails, func(i, j int) bool {
		a, b := rules.Rank(fails[i].Level), rules.Rank(fails[j].Level)
		if a != b {
			return a > b
		}
		return fails[i].RuleID < fails[j].RuleID
	})
	if len(fails) == 0 {
		add("# "+tr.T("script.nothing"), "")
	}
	for _, res := range fails {
		rule := o.Catalog.Get(res.RuleID)
		if rule == nil {
			continue
		}
		t := rule.Text(tr.Lang())
		for _, f := range res.Findings {
			lvl := f.Level
			if lvl == "" {
				lvl = res.Level
			}
			add(sep, "# ["+strings.ToUpper(tr.T("level."+lvl))+"] "+res.RuleID+" — "+oneLine(replaceParams(t.Title, f.Params)))
			if f.Object != "" {
				add("# " + tr.T("script.object") + tr.T("common.colon") + oneLine(f.Object))
			}
			if t.Impact != "" {
				add(wrapComment(tr.T("script.impact") + tr.T("common.colon") + oneLine(t.Impact))...)
			}
			if !f.GPO && t.GPO != "" {
				add(wrapComment(tr.T("report.gpo_where") + tr.T("common.colon") + oneLine(t.GPO))...)
			}
			if f.GPO {
				g := tr.T("script.gpo")
				if t.GPO != "" {
					g += tr.T("common.colon") + oneLine(t.GPO)
				}
				add(wrapComment(g)...)
			}
			add(sep)
			if f.Remediation == "" {
				add("# "+tr.T("script.manual"), "")
				continue
			}
			// Paramètre imposé par GPO : commande donnée pour information seulement (##).
			prefix := "# "
			if f.GPO {
				prefix = "## "
			}
			target := f.Object
			if target == "" {
				target = r.Host.Name
			}
			add(prefix + "Invoke-AplombFix -Id " + q(res.RuleID) + " -Target " + q(oneLine(target)) + " -Fix {")
			for _, l := range strings.Split(f.Remediation, "\n") {
				add(prefix + "    " + strings.TrimRight(l, " \r"))
			}
			add(prefix+"}", "")
		}
	}
	add("Stop-Transcript | Out-Null")

	if _, err := bw.WriteString(bom); err != nil {
		return err
	}
	for _, l := range lines {
		if _, err := bw.WriteString(l + "\r\n"); err != nil {
			return err
		}
	}
	return bw.Flush()
}

// bom est la marque d'ordre des octets UTF-8 (U+FEFF).
const bom = "\xEF\xBB\xBF"

func oneLine(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

// wrapComment coupe un long texte en lignes de commentaire d'environ 78 colonnes.
func wrapComment(s string) []string {
	var out []string
	line := "#"
	for _, w := range strings.Fields(s) {
		if len([]rune(line))+1+len([]rune(w)) > 78 && line != "#" {
			out = append(out, line)
			line = "#  "
		}
		line += " " + w
	}
	return append(out, line)
}
