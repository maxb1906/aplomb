package gui

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	_ "github.com/maxb1906/aplomb/internal/checks/all"
	"github.com/maxb1906/aplomb/internal/collect"
	"github.com/maxb1906/aplomb/internal/i18n"
	"github.com/maxb1906/aplomb/internal/model"
)

// fakeShell enregistre les évènements et les ouvertures demandées.
type fakeShell struct {
	mu     sync.Mutex
	events map[string][]any
	opened []string
	done   chan struct{}
}

func (f *fakeShell) Emit(e string, d any) {
	f.mu.Lock()
	f.events[e] = append(f.events[e], d)
	f.mu.Unlock()
	if e == EventDone || e == EventError {
		f.done <- struct{}{}
	}
}
func (f *fakeShell) Open(p string) error                { f.opened = append(f.opened, p); return nil }
func (f *fakeShell) ChooseImage(string) (string, error) { return "", nil }
func (f *fakeShell) RelaunchElevated() error            { return nil }
func (f *fakeShell) Quit()                              {}

func newTestApp(t *testing.T, fixture string) (*App, *fakeShell) {
	t.Helper()
	bundle, err := i18n.Default()
	if err != nil {
		t.Fatal(err)
	}
	snap, err := model.Load(filepath.Join("..", "..", "testdata", "snapshots", fixture+".json"))
	if err != nil {
		t.Fatal(err)
	}
	a := New("test", t.TempDir(), "fr", bundle)
	a.Collect = func(_ string, progress collect.Progress) (*model.Snapshot, error) {
		for _, s := range []string{"host", "services"} {
			progress(s)
		}
		return snap, nil
	}
	sh := &fakeShell{events: map[string][]any{}, done: make(chan struct{}, 1)}
	a.SetShell(sh)
	return a, sh
}

func TestAuditFlow(t *testing.T) {
	a, sh := newTestApp(t, "vulnerable-workstation")
	if in := a.Init(); in.HasCurrent || in.Strings["gui.nav.audit"] == "" || in.Version != "test" {
		t.Fatalf("init : %+v", in.HasCurrent)
	}
	if err := a.StartAudit(AuditOptions{}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-sh.done:
	case <-time.After(10 * time.Second):
		t.Fatal("audit sans fin")
	}
	if len(sh.events[EventProgress]) != 2 || len(sh.events[EventDone]) != 1 {
		t.Fatalf("évènements : %v", sh.events)
	}
	res := sh.events[EventDone][0].(*Result)
	if res.Score.Grade == "" || len(res.View.Issues) == 0 || res.Files["html"] == "" || res.Files["ps1"] == "" {
		t.Fatalf("résultat incomplet : %+v", res.Files)
	}
	// Le rapport affiché suit la langue de l'interface.
	a.Strings("en")
	if en := a.Current(); en.View.Lang != "en" || en.View.Issues[0].LevelLabel == res.View.Issues[0].LevelLabel {
		t.Errorf("rapport non traduit : %s", en.View.Lang)
	}

	// Accepter un risque met config.yaml et le rapport à jour.
	id := res.View.Issues[0].ID
	if _, err := a.AcceptRisk(id, "  "); err == nil {
		t.Error("justification vide acceptée")
	}
	acc, err := a.AcceptRisk(id, "copieur ancien")
	if err != nil {
		t.Fatal(err)
	}
	if len(acc.View.Accepted) != 1 || acc.View.Accepted[0].ID != id || acc.Score.Counts.Accepted != 1 {
		t.Fatalf("risque accepté absent : %+v", acc.View.Accepted)
	}
	if c := a.GetConfig(); len(c.Disabled) != 1 || c.Disabled[0].Title == "" {
		t.Errorf("config : %+v", c.Disabled)
	}
	rev, err := a.RevokeRisk(id)
	if err != nil || len(rev.View.Accepted) != 0 {
		t.Fatalf("réactivation : %v", err)
	}

	// Historique : un seul rapport (la réévaluation remplace les fichiers).
	h, err := a.History()
	if err != nil || len(h) != 1 {
		t.Fatalf("historique : %v %v", h, err)
	}
	if r, err := a.OpenReport(h[0].Path); err != nil || r.Source != "history" {
		t.Fatalf("ouverture : %v", err)
	}
}

func TestOpenPathRestricted(t *testing.T) {
	a, sh := newTestApp(t, "healthy-workstation")
	inside := filepath.Join(a.DataDir, "rapports", "x.html")
	if err := a.OpenPath(inside); err != nil {
		t.Error(err)
	}
	for _, p := range []string{filepath.Join(a.DataDir, "..", "evil.exe"), os.TempDir(), "/etc/passwd"} {
		if err := a.OpenPath(p); err == nil {
			t.Errorf("%s : ouverture acceptée hors du dossier de données", p)
		}
	}
	if len(sh.opened) != 1 {
		t.Errorf("ouvertures : %v", sh.opened)
	}
	if _, err := a.OpenReport("/etc/passwd"); err == nil {
		t.Error("rapport hors du dossier de données accepté")
	}
}

func TestSaveConfigErrorsAreTranslated(t *testing.T) {
	a, _ := newTestApp(t, "healthy-workstation")
	err := a.SaveConfig(Config{Profile: "portable"})
	if err == nil || !strings.Contains(err.Error(), "portable") || strings.Contains(err.Error(), "audit.bad_profile") {
		t.Errorf("erreur : %v", err)
	}
	if err := a.SaveConfig(Config{Technician: " Tech ", Profile: "server", Formats: []string{"html"}, Disabled: []Disabled{{ID: "SMB-003", Reason: "copieur"}}}); err != nil {
		t.Fatal(err)
	}
	c := a.GetConfig()
	if c.Technician != "Tech" || c.Profile != "server" || len(c.Formats) != 1 || len(c.Disabled) != 1 {
		t.Errorf("relecture : %+v", c)
	}
}

func TestAuditError(t *testing.T) {
	a, sh := newTestApp(t, "healthy-workstation")
	a.Collect = func(string, collect.Progress) (*model.Snapshot, error) { return nil, collect.ErrNotWindows }
	if err := a.StartAudit(AuditOptions{}); err != nil {
		t.Fatal(err)
	}
	<-sh.done
	if msg, _ := sh.events[EventError][0].(string); !strings.Contains(msg, "Windows") {
		t.Errorf("message : %q", msg)
	}
	a.Collect = func(string, collect.Progress) (*model.Snapshot, error) { panic("boom") }
	a.StartAudit(AuditOptions{})
	<-sh.done
	if len(sh.events[EventError]) != 2 {
		t.Error("plantage de la collecte non signalé")
	}
}

func TestWithin(t *testing.T) {
	for _, c := range []struct {
		root, p string
		ok      bool
	}{
		{"/a/b", "/a/b", true}, {"/a/b", "/a/b/c.html", true}, {"/a/b", "/a/bc", false},
		{"/a/b", "/a/b/../c", false}, {"/a/b", "/a", false}, {"/a/b", "/a/b/..x/y", true},
	} {
		if got := within(c.root, c.p); got != c.ok {
			t.Errorf("within(%q, %q) = %v", c.root, c.p, got)
		}
	}
}
