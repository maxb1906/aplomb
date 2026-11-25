package all

import (
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"

	"github.com/maxb1906/aplomb/internal/model"
	"github.com/maxb1906/aplomb/internal/rules"
	"github.com/maxb1906/aplomb/internal/score"
)

func catalog(t *testing.T) *rules.Catalog {
	t.Helper()
	c, err := rules.Default()
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// Chaque règle du YAML a sa logique, et inversement.
func TestCatalogMatchesEvaluators(t *testing.T) {
	c := catalog(t)
	yaml := map[string]bool{}
	for _, r := range c.Rules {
		yaml[r.ID] = true
	}
	for _, id := range rules.Registered() {
		if !yaml[id] {
			t.Errorf("évaluateur %s sans règle dans rules.yaml", id)
		}
		delete(yaml, id)
	}
	for id := range yaml {
		t.Errorf("règle %s sans évaluateur", id)
	}
}

// Chaque règle a une référence et un préfixe d'identifiant cohérent avec sa catégorie.
func TestRuleConventions(t *testing.T) {
	prefix := map[string]string{"system": "SYS", "services": "SVC", "tasks": "TSK", "accounts": "ACC",
		"bitlocker": "BDE", "defender": "DEF", "smb": "SMB", "firewall": "FW"}
	for _, r := range catalog(t).Rules {
		if !strings.HasPrefix(r.ID, prefix[r.Category]+"-") {
			t.Errorf("%s : préfixe attendu %s- pour la catégorie %s", r.ID, prefix[r.Category], r.Category)
		}
		if len(r.Refs) == 0 {
			t.Errorf("%s : aucune référence", r.ID)
		}
		for _, ref := range r.Refs {
			if strings.Contains(strings.ToUpper(ref.Name), "CIS ") || strings.Contains(ref.URL, "cisecurity") {
				t.Errorf("%s : référence CIS interdite", r.ID)
			}
		}
	}
}

func fixture(t *testing.T, name string) *model.Snapshot {
	t.Helper()
	_, file, _, _ := runtime.Caller(0)
	s, err := model.Load(filepath.Join(filepath.Dir(file), "..", "..", "..", "testdata", "snapshots", name+".json"))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func evaluate(t *testing.T, name string, opt rules.Options) map[string]rules.Result {
	t.Helper()
	res, err := catalog(t).Evaluate(fixture(t, name), opt)
	if err != nil {
		t.Fatal(err)
	}
	m := map[string]rules.Result{}
	for _, r := range res {
		m[r.RuleID] = r
	}
	return m
}

// want : "RULE": "status" ou "status/level".
func check(t *testing.T, fixtureName string, got map[string]rules.Result, want map[string]string) {
	t.Helper()
	ids := make([]string, 0, len(want))
	for id := range want {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		r, ok := got[id]
		if !ok {
			t.Errorf("%s : %s absent des résultats", fixtureName, id)
			continue
		}
		st, lvl, _ := strings.Cut(want[id], "/")
		if string(r.Status) != st || (lvl != "" && r.Level != lvl) {
			t.Errorf("%s : %s = %s/%s, attendu %s (%+v)", fixtureName, id, r.Status, r.Level, want[id], r)
		}
	}
}

func TestHealthyWorkstation(t *testing.T) {
	got := evaluate(t, "healthy-workstation", rules.Options{})
	check(t, "healthy", got, map[string]string{
		"SYS-012": "pass", "SYS-013": "pass",
	})
	for id, r := range got {
		if r.Status == rules.Fail {
			t.Errorf("poste sain : %s en défaut (%+v)", id, r.Findings)
		}
	}
	s := score.Compute(mapToSlice(got), catalog(t))
	if s.Score != 100 || s.Grade != "A" {
		t.Errorf("score poste sain = %d %s", s.Score, s.Grade)
	}
}

func TestVulnerableWorkstation(t *testing.T) {
	got := evaluate(t, "vulnerable-workstation", rules.Options{})
	check(t, "vulnerable", got, map[string]string{
		"SYS-012": "fail/critical", "SYS-013": "fail/warning",
	})
	s := score.Compute(mapToSlice(got), catalog(t))
	if !s.Capped && s.RawScore > score.CapScore {
		t.Error("un Critique doit plafonner le score")
	}
	if s.Grade == "A" || s.Grade == "B" {
		t.Errorf("note %s malgré un Critique", s.Grade)
	}
}

func TestNonAdminServer(t *testing.T) {
	got := evaluate(t, "nonadmin-server", rules.Options{})
	check(t, "nonadmin-server", got, map[string]string{
		"SYS-012": "fail/warning",
	})
}

func TestDC(t *testing.T) {
	got := evaluate(t, "dc", rules.Options{})
	check(t, "dc", got, map[string]string{
		"SYS-013": "not_checked",
	})
}

func TestAcceptedRisk(t *testing.T) {
	got := evaluate(t, "vulnerable-workstation", rules.Options{Accepted: map[string]string{"SYS-013": "Vieux PC, remplacement prévu en 2027"}})
	check(t, "accepted", got, map[string]string{"SYS-013": "accepted_risk"})
	if got["SYS-013"].Accepted == "" {
		t.Error("justification absente")
	}
}

func TestProfileOverride(t *testing.T) {
	// Un profil forcé est transmis aux évaluateurs.
	got := evaluate(t, "healthy-workstation", rules.Options{Profile: model.RoleServer})
	if len(got) == 0 {
		t.Fatal("aucun résultat")
	}
}

func mapToSlice(m map[string]rules.Result) []rules.Result {
	out := make([]rules.Result, 0, len(m))
	for _, r := range m {
		out = append(out, r)
	}
	return out
}
