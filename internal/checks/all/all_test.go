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
		"SVC-001": "pass", "SVC-002": "pass", "SVC-003": "pass", "SVC-004": "pass", "SVC-005": "not_applicable",
		"TSK-001": "pass", "TSK-002": "pass", "TSK-003": "pass", "TSK-004": "pass", "TSK-005": "pass",
		"ACC-001": "pass", "ACC-002": "pass", "ACC-003": "pass", "ACC-004": "pass", "ACC-005": "pass",
		"ACC-006": "pass", "ACC-007": "pass", "ACC-008": "pass", "ACC-009": "pass", "ACC-010": "pass",
		"BDE-001": "pass", "BDE-002": "pass", "BDE-003": "pass", "BDE-004": "pass", "BDE-005": "pass", "BDE-006": "pass",
		"DEF-001": "pass", "DEF-002": "pass", "DEF-003": "pass", "DEF-004": "pass", "DEF-005": "pass", "DEF-006": "pass", "DEF-007": "pass",
		"SMB-001": "pass", "SMB-002": "pass", "SMB-003": "pass", "SMB-004": "pass", "SMB-005": "pass", "SMB-006": "pass",
		"FW-001": "pass", "FW-002": "pass", "FW-003": "pass", "FW-004": "pass", "FW-005": "pass",
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
		"SVC-001": "fail/critical", "SVC-002": "fail/critical", "SVC-003": "fail/critical", "SVC-004": "fail/warning",
	})
	objects(t, got["SVC-001"], "VulnSvc", "UnqWarn")
	objects(t, got["SVC-004"], "Updater")
	check(t, "vulnerable", got, map[string]string{
		"TSK-001": "fail/critical", "TSK-002": "fail/warning", "TSK-003": "fail/warning", "TSK-004": "fail/info", "TSK-005": "fail/info",
	})
	// La tâche de l'utilisateur bob n'est pas privilégiée : pas d'élévation.
	objects(t, got["TSK-001"], `\Backup — C:\Scripts\backup.ps1`)
	objects(t, got["TSK-002"], `\Sync`)
	objects(t, got["TSK-003"], `\Updater Check`)
	objects(t, got["TSK-004"], `\Updater Check`)
	objects(t, got["TSK-005"], `\OldTool`)
	objects(t, got["SVC-002"], `WeakBin — C:\ProgramData\WeakVendor\weak.exe`, `WeakBin — C:\ProgramData\WeakVendor`, `DropDir — C:\ProgramData\Drop`)
	if f := finding(got["SVC-002"], `DropDir — C:\ProgramData\Drop`); f == nil || f.Level != "warning" {
		t.Errorf("ajout de fichier seulement → Attention (%+v)", f)
	}
	if f := finding(got["SVC-001"], "UnqWarn"); f == nil || f.Level != "warning" {
		t.Errorf("UnqWarn : dossiers non inscriptibles → Attention (%+v)", f)
	}
	if f := finding(got["SVC-001"], "VulnSvc"); f == nil || !strings.Contains(f.Remediation, `'"C:\Apps Tiers\Vuln App\svc.exe"'`) {
		t.Errorf("remédiation SVC-001 : %+v", f)
	}
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
		"SVC-005": "fail/warning",
		"TSK-001": "pass",
		"ACC-001": "fail/warning", "ACC-007": "not_checked", "ACC-010": "fail/warning",
		"BDE-001": "not_checked", "DEF-002": "not_applicable", "DEF-004": "fail/critical", "DEF-001": "pass",
		"SMB-001": "not_checked", "SMB-002": "not_checked", "SMB-005": "fail/warning",
		"FW-001": "pass", "FW-004": "pass",
	})
	if !got["ACC-001"].GPO || !strings.Contains(got["ACC-010"].Findings[0].Remediation, "OU=Serveurs,DC=corp,DC=example") {
		t.Errorf("domaine : GPO et OU attendues (%+v)", got["ACC-010"])
	}
	if got["ACC-007"].Reason != "requires_admin" {
		t.Error("ACC-007 : raison requires_admin attendue")
	}
	if got["TSK-001"].Note != "partial_tasks" {
		t.Error("sans admin, la vérification des tâches doit être signalée comme partielle")
	}
}

func TestDC(t *testing.T) {
	got := evaluate(t, "dc", rules.Options{})
	check(t, "dc", got, map[string]string{
		"SYS-013": "not_checked",
		"SVC-005": "fail", // spouleur actif sur un DC, même avec une imprimante
		"TSK-001": "not_checked",
		"ACC-001": "fail", "ACC-002": "fail", "ACC-006": "not_applicable", "ACC-007": "pass", "ACC-010": "not_applicable",
		"BDE-001": "not_applicable", "DEF-001": "not_applicable", "DEF-004": "not_applicable",
		"SMB-002": "pass", // SYSVOL et NETLOGON sont lisibles par conception
		"SMB-005": "fail/critical",
		"FW-001":  "not_checked",
	})
}

// Sans admin et sans exclusion imposée par GPO, les exclusions ne sont pas vérifiables.
func TestDefenderExclusionsHidden(t *testing.T) {
	s := fixture(t, "nonadmin-server")
	s.Defender.PolicyExclusions = nil
	res, err := catalog(t).Evaluate(s, rules.Options{})
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range res {
		if r.RuleID == "DEF-004" && (r.Status != rules.NotChecked || r.Reason != "requires_admin") {
			t.Errorf("DEF-004 = %s (%s)", r.Status, r.Reason)
		}
	}
}

// Un antivirus tiers actif rend les contrôles Defender non applicables.
func TestOtherAntivirus(t *testing.T) {
	s := fixture(t, "vulnerable-workstation")
	s.Defender.OtherAV = []string{"ESET Security"}
	res, err := catalog(t).Evaluate(s, rules.Options{})
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range res {
		if r.Category == "defender" && r.Status != rules.NotApplicable {
			t.Errorf("%s = %s, attendu not_applicable", r.RuleID, r.Status)
		}
	}
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

// objects vérifie la liste exacte des objets en défaut.
func objects(t *testing.T, r rules.Result, want ...string) {
	t.Helper()
	var got []string
	for _, f := range r.Findings {
		got = append(got, f.Object)
	}
	sort.Strings(got)
	sort.Strings(want)
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("%s : objets %v, attendu %v", r.RuleID, got, want)
	}
}

func finding(r rules.Result, object string) *rules.Finding {
	for i := range r.Findings {
		if r.Findings[i].Object == object {
			return &r.Findings[i]
		}
	}
	return nil
}
