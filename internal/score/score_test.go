package score

import (
	"testing"

	"github.com/maxb1906/aplomb/internal/rules"
)

const yml = `
- id: SYS-900
  category: system
  level: critical
  refs: [{name: x, url: y}]
  text: {fr: {title: a, summary: b}, en: {title: a, summary: b}}
- id: SYS-901
  category: system
  level: warning
  refs: [{name: x, url: y}]
  text: {fr: {title: a, summary: b}, en: {title: a, summary: b}}
- id: SVC-900
  category: services
  level: info
  refs: [{name: x, url: y}]
  text: {fr: {title: a, summary: b}, en: {title: a, summary: b}}
`

func TestCompute(t *testing.T) {
	cat, err := rules.Parse([]byte(yml))
	if err != nil {
		t.Fatal(err)
	}
	res := []rules.Result{
		{RuleID: "SYS-900", Category: "system", Status: rules.Pass, Level: "critical"},
		{RuleID: "SYS-901", Category: "system", Status: rules.Fail, Level: "warning"},
		{RuleID: "SVC-900", Category: "services", Status: rules.NotChecked, Level: "info"},
	}
	s := Compute(res, cat)
	// 10 / (10 + 4) = 71 %
	if s.Score != 71 || s.Grade != "C" || s.Capped {
		t.Errorf("score = %+v", s)
	}
	if s.Coverage != 66 {
		t.Errorf("couverture = %d", s.Coverage)
	}
	if len(s.Categories) != 2 || s.Categories[1].Score != -1 || s.Categories[1].Grade != "-" {
		t.Errorf("catégories = %+v", s.Categories)
	}

	// Un Critique en défaut plafonne la note.
	res = []rules.Result{
		{RuleID: "SYS-900", Category: "system", Status: rules.Fail, Level: "critical"},
	}
	for i := 0; i < 30; i++ {
		res = append(res, rules.Result{RuleID: "SYS-901", Category: "system", Status: rules.Pass})
	}
	s = Compute(res, cat)
	if !s.Capped || s.Score != CapScore || s.Grade != "C" || s.RawScore <= CapScore {
		t.Errorf("plafond : %+v", s)
	}
}

func TestGrade(t *testing.T) {
	for in, want := range map[int]string{100: "A", 90: "A", 89: "B", 75: "B", 60: "C", 40: "D", 0: "E", -1: "-"} {
		if g := Grade(in); g != want {
			t.Errorf("Grade(%d) = %s, attendu %s", in, g, want)
		}
	}
}
