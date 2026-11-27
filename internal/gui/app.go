// Package gui est l'interface graphique d'Aplomb (Wails + WebView2).
//
// Les méthodes exportées d'App sont appelées par le frontend (frontend/src) ;
// elles ne font que réutiliser internal/app, comme la ligne de commande. Tout
// ce qui dépend de Windows (fenêtre, boîtes de dialogue, ouverture de
// fichiers, élévation) passe par l'interface Shell, ce qui permet de tester
// App sous Linux.
package gui

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"

	"github.com/maxb1906/aplomb/internal/app"
	"github.com/maxb1906/aplomb/internal/collect"
	"github.com/maxb1906/aplomb/internal/config"
	"github.com/maxb1906/aplomb/internal/i18n"
	"github.com/maxb1906/aplomb/internal/model"
	"github.com/maxb1906/aplomb/internal/report"
	"github.com/maxb1906/aplomb/internal/rules"
	"github.com/maxb1906/aplomb/internal/score"
)

// Évènements émis vers le frontend.
const (
	EventProgress = "audit:progress"
	EventDone     = "audit:done"
	EventError    = "audit:error"
)

// Shell regroupe ce qui dépend du système et de la fenêtre.
type Shell interface {
	Emit(event string, data any)
	Open(path string) error
	ChooseImage(title string) (string, error)
	RelaunchElevated() error
	Quit()
}

// Collector lit la configuration de la machine (collect.Collect par défaut).
type Collector func(version string, progress collect.Progress) (*model.Snapshot, error)

// App est l'objet lié au frontend.
type App struct {
	Version string
	DataDir string
	Bundle  *i18n.Bundle
	Collect Collector

	shell Shell
	lang  string

	mu      sync.Mutex
	running bool
	current *current
}

// current est le rapport affiché.
type current struct {
	out    *app.Output
	source string // "audit" ou "history"
}

// New crée l'application ; lang est la langue de l'interface au démarrage.
func New(version, dataDir, lang string, bundle *i18n.Bundle) *App {
	return &App{Version: version, DataDir: dataDir, Bundle: bundle, Collect: collect.Collect, lang: lang}
}

// SetShell branche la fenêtre (appelé au démarrage de Wails).
func (a *App) SetShell(s Shell) { a.shell = s }

// ---- Démarrage, langue, configuration ----

// Init est ce dont l'interface a besoin au démarrage.
type Init struct {
	Version    string            `json:"version"`
	Lang       string            `json:"lang"`
	Languages  []string          `json:"languages"`
	Strings    map[string]string `json:"strings"`
	CanAudit   bool              `json:"can_audit"`
	Elevated   bool              `json:"elevated"`
	Hostname   string            `json:"hostname"`
	DataDir    string            `json:"data_dir"`
	Sections   []string          `json:"sections"`
	Config     Config            `json:"config"`
	ConfigErr  string            `json:"config_error,omitempty"`
	HasCurrent bool              `json:"has_current"`
}

// Init renvoie l'état initial de l'interface.
func (a *App) Init() Init {
	cfg, err := app.LoadConfig(a.DataDir)
	host, _ := os.Hostname()
	in := Init{
		Version: a.Version, Lang: a.uiLang(), Languages: a.Bundle.Languages(), Strings: a.Bundle.Catalog(a.uiLang()),
		CanAudit: runtime.GOOS == "windows", Elevated: collect.Elevated(), Hostname: host,
		DataDir: a.DataDir, Sections: collect.Sections(), Config: toConfig(cfg),
	}
	if err != nil {
		in.ConfigErr = a.tr().T("cli.error", "error", err.Error())
	}
	a.mu.Lock()
	in.HasCurrent = a.current != nil
	a.mu.Unlock()
	return in
}

// Strings change la langue de l'interface et renvoie ses traductions.
func (a *App) Strings(lang string) map[string]string {
	a.mu.Lock()
	if a.Bundle.Has(lang) {
		a.lang = lang
	}
	a.mu.Unlock()
	return a.Bundle.Catalog(a.uiLang())
}

// uiLang renvoie la langue de l'interface (lue aussi par la goroutine d'audit).
func (a *App) uiLang() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.lang
}

func (a *App) tr() *i18n.Translator { return a.Bundle.Translator(a.uiLang()) }

// Config est la configuration éditée dans l'écran Réglages.
type Config struct {
	Technician string     `json:"technician"`
	Company    string     `json:"company"`
	Logo       string     `json:"logo"`
	Lang       string     `json:"lang"`
	ReportLang string     `json:"report_lang"`
	Profile    string     `json:"profile"` // "", workstation, server, dc
	Formats    []string   `json:"formats"`
	Disabled   []Disabled `json:"disabled"`
}

// Disabled est une règle désactivée (risque accepté).
type Disabled struct {
	ID     string `json:"id"`
	Reason string `json:"reason"`
	Title  string `json:"title,omitempty"`
}

func toConfig(c *config.Config) Config {
	profile, _ := app.ParseProfile(c.Profile)
	out := Config{Technician: c.Technician, Company: c.Company, Logo: c.Logo, Lang: c.Lang, ReportLang: c.ReportLang, Profile: profile, Formats: c.Formats}
	if len(out.Formats) == 0 {
		out.Formats = append([]string(nil), report.Formats...)
	}
	for _, d := range c.DisabledRules {
		out.Disabled = append(out.Disabled, Disabled{ID: d.ID, Reason: d.Reason})
	}
	return out
}

// GetConfig relit config.yaml (titres des règles désactivées dans la langue de l'interface).
func (a *App) GetConfig() Config {
	cfg, _ := app.LoadConfig(a.DataDir)
	c := toConfig(cfg)
	if cat, err := rules.Default(); err == nil {
		for i, d := range c.Disabled {
			if r := cat.Get(d.ID); r != nil {
				c.Disabled[i].Title = r.Text(a.uiLang()).Title
			}
		}
	}
	return c
}

// SaveConfig enregistre la configuration ; l'erreur renvoyée est traduite.
func (a *App) SaveConfig(c Config) error {
	cfg, _ := app.LoadConfig(a.DataDir)
	cfg.Technician, cfg.Company, cfg.Logo = strings.TrimSpace(c.Technician), strings.TrimSpace(c.Company), strings.TrimSpace(c.Logo)
	cfg.Lang, cfg.ReportLang, cfg.Profile, cfg.Formats = c.Lang, c.ReportLang, c.Profile, c.Formats
	cfg.DisabledRules = nil
	for _, d := range c.Disabled {
		if d.ID != "" {
			cfg.DisabledRules = append(cfg.DisabledRules, config.DisabledRule{ID: d.ID, Reason: strings.TrimSpace(d.Reason)})
		}
	}
	return a.saveConfig(cfg)
}

func (a *App) saveConfig(cfg *config.Config) error {
	_, err := app.SaveConfig(a.DataDir, cfg, a.Bundle, a.tr().T("config.header"))
	return a.userError(err)
}

// userError traduit une erreur pour l'afficher dans l'interface.
func (a *App) userError(err error) error {
	var ie *app.InputError
	switch {
	case err == nil:
		return nil
	case errors.As(err, &ie):
		return errors.New(ie.Message(a.tr()))
	case errors.Is(err, app.ErrNotReport):
		return errors.New(a.tr().T("gui.error.not_report"))
	case errors.Is(err, collect.ErrNotWindows):
		return errors.New(a.tr().T("audit.not_windows"))
	}
	return errors.New(a.tr().T("cli.error", "error", err.Error()))
}

// ChooseLogo ouvre un sélecteur d'image ; renvoie "" si l'utilisateur annule.
func (a *App) ChooseLogo() (string, error) {
	if a.shell == nil {
		return "", nil
	}
	p, err := a.shell.ChooseImage(a.tr().T("gui.settings.logo_choose"))
	if err != nil || p == "" {
		return "", a.userError(err)
	}
	// Un logo placé dans aplomb-data est enregistré en relatif (clé USB : la lettre change).
	if rel, err := filepath.Rel(a.DataDir, p); err == nil && !strings.HasPrefix(rel, "..") {
		return rel, nil
	}
	return p, nil
}

// ---- Audit ----

// AuditOptions règle un audit lancé depuis l'interface.
type AuditOptions struct {
	Profile    string `json:"profile"`
	ReportLang string `json:"report_lang"`
}

// Progress est émis au début de chaque section de collecte.
type Progress struct {
	Section string `json:"section"`
	Label   string `json:"label"`
	Index   int    `json:"index"`
	Total   int    `json:"total"`
}

// StartAudit lance la collecte en arrière-plan ; l'avancement et le résultat
// arrivent par évènements (audit:progress, audit:done, audit:error).
func (a *App) StartAudit(o AuditOptions) error {
	a.mu.Lock()
	if a.running {
		a.mu.Unlock()
		return errors.New(a.tr().T("gui.error.running"))
	}
	a.running = true
	a.mu.Unlock()
	go func() {
		defer func() {
			a.mu.Lock()
			a.running = false
			a.mu.Unlock()
		}()
		res, err := a.runAudit(o)
		if err != nil {
			a.emit(EventError, err.Error())
			return
		}
		a.emit(EventDone, res)
	}()
	return nil
}

// RunAuditSync fait l'audit sans évènement de fin (tests, jeu de démonstration).
func (a *App) RunAuditSync(o AuditOptions) (*Result, error) { return a.runAudit(o) }

// runAudit fait l'audit complet ; les erreurs sont déjà traduites.
func (a *App) runAudit(o AuditOptions) (res *Result, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = a.userError(errors.New(panicText(r)))
		}
	}()
	names := collect.Sections()
	index := map[string]int{}
	for i, n := range names {
		index[n] = i
	}
	snap, err := a.Collect(a.Version, func(section string) {
		a.emit(EventProgress, Progress{Section: section, Label: a.tr().T("section." + section), Index: index[section], Total: len(names)})
	})
	if err != nil {
		return nil, a.userError(err)
	}
	cfg, _ := app.LoadConfig(a.DataDir)
	out, err := app.Produce(snap, cfg, a.Bundle, app.Request{Version: a.Version, Profile: o.Profile, ReportLang: o.ReportLang, UILang: a.uiLang(), DataDir: a.DataDir})
	if err != nil {
		return nil, a.userError(err)
	}
	a.setCurrent(out, "audit")
	return a.result(), nil
}

func (a *App) emit(event string, data any) {
	if a.shell != nil {
		a.shell.Emit(event, data)
	}
}

func (a *App) setCurrent(out *app.Output, source string) {
	a.mu.Lock()
	a.current = &current{out: out, source: source}
	a.mu.Unlock()
}

// ---- Rapport affiché ----

// Result est le rapport affiché, mis en forme dans la langue de l'interface.
type Result struct {
	Source   string            `json:"source"`
	Meta     report.Meta       `json:"meta"`
	Score    score.Score       `json:"score"`
	View     *report.View      `json:"view"`
	Dir      string            `json:"dir"`
	Files    map[string]string `json:"files"` // format → chemin
	Elevated bool              `json:"elevated"`
}

func (a *App) result() *Result {
	a.mu.Lock()
	cur := a.current
	a.mu.Unlock()
	if cur == nil {
		return nil
	}
	cat, err := rules.Default()
	if err != nil {
		return nil
	}
	rep := cur.out.Report
	cfg, _ := app.LoadConfig(a.DataDir)
	view := report.BuildView(rep, report.Options{Translator: a.tr(), Catalog: cat, LogoPath: cfg.LogoPath(a.DataDir)})
	files := map[string]string{}
	for _, p := range cur.out.Paths {
		switch {
		case strings.HasSuffix(p, "_remediation.ps1"):
			files["ps1"] = p
		default:
			files[strings.TrimPrefix(filepath.Ext(p), ".")] = p
		}
	}
	return &Result{Source: cur.source, Meta: rep.Meta, Score: rep.Score, View: view, Dir: cur.out.Dir, Files: files, Elevated: rep.Meta.Elevated}
}

// Current renvoie le rapport affiché dans la langue courante (nil si aucun).
func (a *App) Current() *Result { return a.result() }

// History liste les rapports déjà produits dans aplomb-data.
func (a *App) History() ([]app.Entry, error) {
	h, err := app.History(app.ReportsDir(a.DataDir))
	return h, a.userError(err)
}

// OpenReport charge un rapport JSON de l'historique.
func (a *App) OpenReport(path string) (*Result, error) {
	if !a.inDataDir(path) {
		return nil, errors.New(a.tr().T("gui.error.outside"))
	}
	rep, err := app.LoadReport(path)
	if err != nil {
		return nil, a.userError(err)
	}
	base := strings.TrimSuffix(path, ".json")
	paths := []string{}
	for _, p := range []string{base + ".html", base + ".md", path, base + "_remediation.ps1"} {
		if _, err := os.Stat(p); err == nil {
			paths = append(paths, p)
		}
	}
	a.setCurrent(&app.Output{Report: rep, Dir: filepath.Dir(path), Paths: paths}, "history")
	return a.result(), nil
}

// AcceptRisk désactive une règle avec sa justification (config.yaml), puis
// réévalue le rapport affiché et réécrit ses fichiers.
func (a *App) AcceptRisk(ruleID, reason string) (*Result, error) {
	reason = strings.TrimSpace(reason)
	if reason == "" {
		return nil, errors.New(a.tr().T("gui.error.reason"))
	}
	cfg, _ := app.LoadConfig(a.DataDir)
	kept := cfg.DisabledRules[:0]
	for _, d := range cfg.DisabledRules {
		if d.ID != ruleID {
			kept = append(kept, d)
		}
	}
	cfg.DisabledRules = append(kept, config.DisabledRule{ID: ruleID, Reason: reason})
	if err := a.saveConfig(cfg); err != nil {
		return nil, err
	}
	return a.reevaluate(cfg)
}

// RevokeRisk réactive une règle désactivée et réévalue le rapport affiché.
func (a *App) RevokeRisk(ruleID string) (*Result, error) {
	cfg, _ := app.LoadConfig(a.DataDir)
	kept := cfg.DisabledRules[:0]
	for _, d := range cfg.DisabledRules {
		if d.ID != ruleID {
			kept = append(kept, d)
		}
	}
	cfg.DisabledRules = kept
	if err := a.saveConfig(cfg); err != nil {
		return nil, err
	}
	return a.reevaluate(cfg)
}

// reevaluate réapplique les règles au snapshot du rapport affiché, dans le même dossier.
func (a *App) reevaluate(cfg *config.Config) (*Result, error) {
	a.mu.Lock()
	cur := a.current
	a.mu.Unlock()
	if cur == nil {
		return nil, nil
	}
	rep := cur.out.Report
	if rep.Collection == nil {
		return nil, errors.New(a.tr().T("gui.error.no_collection"))
	}
	var formats []string
	if cur.source == "history" {
		for _, p := range cur.out.Paths {
			switch {
			case strings.HasSuffix(p, "_remediation.ps1"):
				formats = append(formats, "ps1")
			default:
				formats = append(formats, strings.TrimPrefix(filepath.Ext(p), "."))
			}
		}
	}
	out, err := app.Produce(rep.Collection, cfg, a.Bundle, app.Request{
		Version: a.Version, Profile: rep.Meta.Profile, ReportLang: rep.Meta.Lang, UILang: a.uiLang(),
		Formats: formats, OutBase: filepath.Dir(cur.out.Dir), DataDir: a.DataDir,
	})
	if err != nil {
		return nil, a.userError(err)
	}
	a.setCurrent(out, cur.source)
	return a.result(), nil
}

// ---- Système ----

// OpenPath ouvre un rapport ou un dossier avec l'application associée.
// Seuls les fichiers d'aplomb-data et du rapport affiché sont acceptés.
func (a *App) OpenPath(path string) error {
	if a.shell == nil {
		return nil
	}
	if !a.inDataDir(path) && !a.inCurrentDir(path) {
		return errors.New(a.tr().T("gui.error.outside"))
	}
	return a.userError(a.shell.Open(path))
}

// OpenDataDir ouvre aplomb-data dans l'Explorateur.
func (a *App) OpenDataDir() error {
	if err := os.MkdirAll(a.DataDir, 0o755); err != nil {
		return a.userError(err)
	}
	return a.OpenPath(a.DataDir)
}

// RelaunchAdmin relance Aplomb en administrateur (invite UAC) puis ferme cette fenêtre.
func (a *App) RelaunchAdmin() error {
	if a.shell == nil {
		return nil
	}
	if err := a.shell.RelaunchElevated(); err != nil {
		return errors.New(a.tr().T("gui.error.elevate", "error", err.Error()))
	}
	a.shell.Quit()
	return nil
}

func (a *App) inDataDir(p string) bool { return within(a.DataDir, p) }

func (a *App) inCurrentDir(p string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.current != nil && within(a.current.out.Dir, p)
}

// within indique que p est root ou se trouve dessous.
func within(root, p string) bool {
	r, err1 := filepath.Abs(root)
	q, err2 := filepath.Abs(p)
	if err1 != nil || err2 != nil {
		return false
	}
	rel, err := filepath.Rel(r, q)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

func panicText(r any) string { return fmt.Sprintf("panic: %v", r) }
