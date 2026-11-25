package report

import (
	"bytes"
	"encoding/json"
	"html/template"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	_ "github.com/maxb1906/aplomb/internal/checks/all"
	"github.com/maxb1906/aplomb/internal/i18n"
	"github.com/maxb1906/aplomb/internal/model"
	"github.com/maxb1906/aplomb/internal/rules"
)

func build(t *testing.T, fixture string, accepted map[string]string) (*Report, Options) {
	t.Helper()
	_, file, _, _ := runtime.Caller(0)
	s, err := model.Load(filepath.Join(filepath.Dir(file), "..", "..", "testdata", "snapshots", fixture+".json"))
	if err != nil {
		t.Fatal(err)
	}
	cat, err := rules.Default()
	if err != nil {
		t.Fatal(err)
	}
	res, err := cat.Evaluate(s, rules.Options{Accepted: accepted})
	if err != nil {
		t.Fatal(err)
	}
	b, _ := i18n.Default()
	r := Build(s, res, cat, Meta{Version: "test", Lang: "fr", Technician: "Ada <Lovelace>", GeneratedAt: time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)})
	return r, Options{Translator: b.Translator("fr"), Catalog: cat}
}

func TestHTML(t *testing.T) {
	r, o := build(t, "vulnerable-workstation", map[string]string{"SYS-013": "Remplacement <prévu>"})
	var b bytes.Buffer
	if err := HTML(&b, r, o); err != nil {
		t.Fatal(err)
	}
	h := b.String()
	for _, want := range []string{
		"<!doctype html>", "PC-ACCUEIL-01", "CONFIDENTIEL", "Mises à jour Windows en retard",
		`class="copy"`, "Ada &lt;Lovelace&gt;", "Remplacement &lt;prévu&gt;", "Risques acceptés", "<style>",
	} {
		if !strings.Contains(h, want) {
			t.Errorf("HTML : %q absent", want)
		}
	}
	if strings.Contains(h, "ZgotmplZ") || strings.Contains(h, "report.") || strings.Contains(h, "{date}") {
		t.Error("HTML : valeur non traduite ou filtrée")
	}
	if strings.Contains(h, "http://") && !strings.Contains(h, "https://") {
		t.Error("ressource externe inattendue")
	}
}

func TestMarkdownEN(t *testing.T) {
	r, o := build(t, "vulnerable-workstation", nil)
	b0, _ := i18n.Default()
	o.Translator = b0.Translator("en")
	var b bytes.Buffer
	if err := Markdown(&b, r, o); err != nil {
		t.Fatal(err)
	}
	md := b.String()
	for _, want := range []string{"# Security audit — PC-ACCUEIL-01", "CONFIDENTIAL", "Windows updates are overdue", "```powershell", "| Category |"} {
		if !strings.Contains(md, want) {
			t.Errorf("Markdown : %q absent\n%s", want, md)
		}
	}
}

func TestJSONShape(t *testing.T) {
	r, _ := build(t, "healthy-workstation", nil)
	var b bytes.Buffer
	if err := JSON(&b, r); err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b.Bytes(), &m); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"meta", "host", "checks", "score", "collection"} {
		if m[k] == nil {
			t.Errorf("clé %s absente", k)
		}
	}
}

func TestWriteAndDir(t *testing.T) {
	if got := Dir("/x", `PC ACCUEIL/01`); got != filepath.Join("/x", "PC_ACCUEIL_01") {
		t.Error(got)
	}
	r, o := build(t, "healthy-workstation", nil)
	dir := t.TempDir()
	paths, err := Write(dir, "2026-11-20_1200", []string{"html", "json"}, r, o)
	if err != nil || len(paths) != 2 {
		t.Fatalf("%v %v", paths, err)
	}
}

func TestLogoOnlyLocalImages(t *testing.T) {
	if logoURI(filepath.Join(t.TempDir(), "absent.png")) != "" {
		t.Error("logo absent")
	}
	var _ template.URL
}

func TestReplaceParams(t *testing.T) {
	if got := replaceParams("Le {a} et {b}", map[string]string{"a": "x"}); got != "Le x et {b}" {
		t.Error(got)
	}
}
