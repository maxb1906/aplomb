package app

import (
	"errors"
	"path/filepath"
	"testing"

	_ "github.com/maxb1906/aplomb/internal/checks/all"
	"github.com/maxb1906/aplomb/internal/config"
	"github.com/maxb1906/aplomb/internal/i18n"
	"github.com/maxb1906/aplomb/internal/model"
	"github.com/maxb1906/aplomb/internal/rules"
)

func TestParseProfile(t *testing.T) {
	for in, want := range map[string]string{"poste": "workstation", "Serveur": "server", "server": "server", "dc": "dc", "": ""} {
		if got, ok := ParseProfile(in); !ok || got != want {
			t.Errorf("%q → %q", in, got)
		}
	}
	if _, ok := ParseProfile("portable"); ok {
		t.Error("profil inconnu accepté")
	}
}

func fixture(t *testing.T, name string) *model.Snapshot {
	t.Helper()
	s, err := model.Load(filepath.Join("..", "..", "testdata", "snapshots", name+".json"))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// Produce écrit les rapports, l'historique les retrouve et LoadReport relit le JSON.
func TestProduceHistoryLoad(t *testing.T) {
	bundle, err := i18n.Default()
	if err != nil {
		t.Fatal(err)
	}
	data := t.TempDir()
	cfg := &config.Config{}
	out, err := Produce(fixture(t, "vulnerable-workstation"), cfg, bundle, Request{Version: "test", UILang: "fr", DataDir: data})
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Paths) != 4 || out.HTMLPath() == "" {
		t.Fatalf("fichiers : %v", out.Paths)
	}
	if _, err := Produce(fixture(t, "healthy-workstation"), cfg, bundle, Request{Version: "test", UILang: "en", DataDir: data, Formats: []string{"json"}}); err != nil {
		t.Fatal(err)
	}
	h, err := History(ReportsDir(data))
	if err != nil || len(h) != 2 {
		t.Fatalf("historique : %v %v", h, err)
	}
	if h[0].CollectedAt.Before(h[1].CollectedAt) {
		t.Error("historique non trié du plus récent au plus ancien")
	}
	for _, e := range h {
		if e.Grade == "" || e.Host == "" {
			t.Errorf("entrée incomplète : %+v", e)
		}
		rep, err := LoadReport(e.Path)
		if err != nil || rep.Collection == nil {
			t.Fatalf("%s : %v", e.Path, err)
		}
	}
	// Accepter un risque puis réévaluer remplace les mêmes fichiers.
	vuln := out.Report
	failed := ""
	for _, c := range vuln.Checks {
		if c.Status == rules.Fail {
			failed = c.RuleID
			break
		}
	}
	cfg.DisabledRules = []config.DisabledRule{{ID: failed, Reason: "test"}}
	again, err := Produce(vuln.Collection, cfg, bundle, Request{Version: "test", UILang: "fr", DataDir: data})
	if err != nil {
		t.Fatal(err)
	}
	if again.Paths[0] != out.Paths[0] || again.Report.Score.Counts.Accepted != 1 {
		t.Errorf("réévaluation : %v, acceptés %d", again.Paths, again.Report.Score.Counts.Accepted)
	}
	if h, _ := History(ReportsDir(data)); len(h) != 2 {
		t.Errorf("la réévaluation a créé un nouveau rapport : %d", len(h))
	}
}

func TestInputErrors(t *testing.T) {
	bundle, _ := i18n.Default()
	var ie *InputError
	_, err := Produce(fixture(t, "dc"), &config.Config{}, bundle, Request{Profile: "portable", UILang: "fr", DataDir: t.TempDir()})
	if !errors.As(err, &ie) || ie.Key != "audit.bad_profile" {
		t.Errorf("profil : %v", err)
	}
	_, err = Produce(fixture(t, "dc"), &config.Config{}, bundle, Request{Formats: []string{"pdf"}, UILang: "fr", DataDir: t.TempDir()})
	if !errors.As(err, &ie) || ie.Key != "audit.bad_format" {
		t.Errorf("format : %v", err)
	}
	if _, err := SaveConfig(t.TempDir(), &config.Config{Lang: "de"}, bundle, "#"); !errors.As(err, &ie) {
		t.Errorf("langue : %v", err)
	}
	dir := t.TempDir()
	if _, err := SaveConfig(dir, &config.Config{Technician: "Tech", Profile: "serveur"}, bundle, "# test"); err != nil {
		t.Fatal(err)
	}
	if c, err := LoadConfig(dir); err != nil || c.Technician != "Tech" || c.Profile != "serveur" {
		t.Errorf("relecture : %+v %v", c, err)
	}
}
