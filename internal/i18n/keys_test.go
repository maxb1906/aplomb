package i18n

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// Toutes les clés citées dans le code et les modèles existent dans les
// catalogues, y compris les clés construites (catégories, statuts, notes…).
func TestUsedKeysExist(t *testing.T) {
	b, err := Default()
	if err != nil {
		t.Fatal(err)
	}
	have := map[string]bool{}
	for _, k := range b.Keys(Fallback) {
		have[k] = true
	}
	root := filepath.Join("..", "..")
	reKey := regexp.MustCompile(`(?:\bT\(|\bt\s)"([a-z0-9_]+\.[a-z0-9_.\-]+)"`)
	reNote := regexp.MustCompile(`(?:rules\.NA\(|Note\s*=\s*)"([a-z_]+)"`)
	used := map[string]string{}
	err = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && (d.Name() == ".git" || d.Name() == "dist" || d.Name() == "testdata") {
			return filepath.SkipDir
		}
		ext := filepath.Ext(p)
		if ext != ".go" && ext != ".html" && ext != ".md" || strings.HasSuffix(p, "_test.go") {
			return nil
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		for _, m := range reKey.FindAllStringSubmatch(string(data), -1) {
			if !strings.HasSuffix(m[1], ".") { // préfixe d'une clé construite
				used[m[1]] = p
			}
		}
		for _, m := range reNote.FindAllStringSubmatch(string(data), -1) {
			used["note."+m[1]] = p
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	// Clés construites dynamiquement.
	for _, c := range []string{"system", "services", "tasks", "accounts", "bitlocker", "defender", "smb", "firewall"} {
		used["category."+c], used["section."+c] = "dyn", "dyn"
	}
	for _, s := range []string{"pass", "fail", "not_checked", "not_applicable", "accepted_risk"} {
		used["status."+s] = "dyn"
	}
	for _, l := range []string{"info", "warning", "critical"} {
		used["level."+l] = "dyn"
	}
	for _, r := range []string{"workstation", "server", "dc"} {
		used["role."+r] = "dyn"
	}
	for _, r := range []string{"requires_admin", "error", "absent"} {
		used["reason."+r] = "dyn"
	}
	for _, j := range []string{"domain", "workgroup", "unknown"} {
		used["join."+j] = "dyn"
	}
	for _, g := range []string{"A", "B", "C", "D", "E"} {
		used["summary.grade."+g] = "dyn"
	}
	used["section.host"], used["note.profile"], used["note.absent"] = "dyn", "dyn", "dyn"
	for k, where := range used {
		if !have[k] {
			t.Errorf("clé %q utilisée (%s) mais absente des traductions", k, where)
		}
	}
}
