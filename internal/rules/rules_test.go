package rules

import (
	"strings"
	"testing"

	"github.com/maxb1906/aplomb/internal/model"
)

func TestDefaultCatalogParses(t *testing.T) {
	c, err := Default()
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Rules) == 0 {
		t.Fatal("catalogue vide")
	}
}

func TestParseRejects(t *testing.T) {
	base := "  refs: [{name: x, url: y}]\n  text: {fr: {title: a, summary: b}, en: {title: a, summary: b}}\n"
	cases := map[string]string{
		"catégorie": "- id: X-1\n  category: nope\n  level: info\n" + base,
		"niveau":    "- id: X-1\n  category: system\n  level: grave\n" + base,
		"profil":    "- id: X-1\n  category: system\n  level: info\n  profiles: [laptop]\n" + base,
		"doublon":   "- id: X-1\n  category: system\n  level: info\n" + base + "- id: X-1\n  category: system\n  level: info\n" + base,
		"texte en":  "- id: X-1\n  category: system\n  level: info\n  text: {fr: {title: a, summary: b}}\n",
		"modèle":    "- id: X-1\n  category: system\n  level: info\n  remediation: \"{{.x\"\n" + base,
	}
	for name, y := range cases {
		if _, err := Parse([]byte(y)); err == nil {
			t.Errorf("%s : erreur attendue", name)
		}
	}
}

func TestRemediationQuoting(t *testing.T) {
	c, err := Parse([]byte(`
- id: SVC-1
  category: services
  level: info
  remediation: "Stop-Service -Name {{ps .name}}"
  text: {fr: {title: a, summary: b}, en: {title: a, summary: b}}
`))
	if err != nil {
		t.Fatal(err)
	}
	got, err := c.Get("SVC-1").RenderRemediation(map[string]string{"name": "O'Brien svc"})
	if err != nil || got != "Stop-Service -Name 'O''Brien svc'" {
		t.Errorf("%q %v", got, err)
	}
	if _, err := c.Get("SVC-1").RenderRemediation(nil); err == nil {
		t.Error("paramètre manquant : erreur attendue")
	}
}

func TestEvaluateProfilesAndPanics(t *testing.T) {
	c, err := Parse([]byte(`
- id: TST-1
  category: system
  level: warning
  profiles: [dc]
  text: {fr: {title: a, summary: b}, en: {title: a, summary: b}}
- id: TST-2
  category: system
  level: warning
  text: {fr: {title: a, summary: b}, en: {title: a, summary: b}}
`))
	if err != nil {
		t.Fatal(err)
	}
	Register("TST-1", func(*Ctx) Outcome { return Failed() })
	Register("TST-2", func(*Ctx) Outcome { panic("boum") })
	defer func() { delete(evaluators, "TST-1"); delete(evaluators, "TST-2") }()
	res, err := c.Evaluate(&model.Snapshot{Host: model.Host{Role: model.RoleWorkstation}}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if res[0].Status != NotApplicable || res[0].Note != "profile" {
		t.Errorf("profil : %+v", res[0])
	}
	if res[1].Status != NotChecked || !strings.Contains(res[1].ReasonDetail, "boum") {
		t.Errorf("panic : %+v", res[1])
	}
}
