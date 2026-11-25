package report

import (
	"bytes"
	"strings"
	"testing"

	"github.com/maxb1906/aplomb/internal/rules"
)

func TestScript(t *testing.T) {
	r, o := build(t, "vulnerable-workstation", map[string]string{"SYS-013": "accepté"})
	var b bytes.Buffer
	if err := Script(&b, r, o); err != nil {
		t.Fatal(err)
	}
	s := b.String()
	if !strings.HasPrefix(s, bom+"#Requires -Version 5.1\r\n") {
		t.Error("BOM UTF-8 et #Requires attendus en tête")
	}
	if strings.Contains(strings.ReplaceAll(s, "\r\n", ""), "\n") {
		t.Error("fins de ligne CRLF attendues")
	}
	for _, want := range []string{"SupportsShouldProcess", "Start-Transcript", "IsInRole", "$env:COMPUTERNAME -ne 'PC-ACCUEIL-01'"} {
		if !strings.Contains(s, want) {
			t.Errorf("%q absent", want)
		}
	}
	// Aucune correction active : toutes les lignes de commande sont commentées.
	for _, l := range strings.Split(s, "\r\n") {
		if strings.HasPrefix(l, "Invoke-AplombFix") {
			t.Fatalf("correction non commentée : %s", l)
		}
	}
	// Un bloc par constat en défaut (hors risques acceptés), GPO en « ## ».
	n := 0
	for _, res := range r.Checks {
		if res.Status == rules.Fail {
			for _, f := range res.Findings {
				if f.Remediation != "" {
					n++
				}
			}
		}
	}
	got := strings.Count(s, "\r\n# Invoke-AplombFix ") + strings.Count(s, "\r\n## Invoke-AplombFix ")
	if got != n || n == 0 {
		t.Errorf("%d blocs, attendu %d", got, n)
	}
	if strings.Contains(s, "'SYS-013'") {
		t.Error("un risque accepté ne doit pas figurer dans le script")
	}
	if !strings.Contains(s, "## Invoke-AplombFix -Id 'DEF-001'") {
		t.Error("DEF-001 imposé par stratégie : bloc en « ## » attendu")
	}
}

func TestScriptHealthy(t *testing.T) {
	r, o := build(t, "healthy-workstation", nil)
	var b bytes.Buffer
	if err := Script(&b, r, o); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(b.String(), "Invoke-AplombFix -Id") {
		t.Error("poste sain : aucune correction attendue")
	}
}

func TestWrapComment(t *testing.T) {
	for _, l := range wrapComment(strings.Repeat("mot ", 60)) {
		if len(l) > 80 || !strings.HasPrefix(l, "#") {
			t.Errorf("ligne %q", l)
		}
	}
}
