package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/maxb1906/aplomb/internal/collect"
	"github.com/maxb1906/aplomb/internal/config"
	"github.com/maxb1906/aplomb/internal/model"
	"github.com/maxb1906/aplomb/internal/report"
	"github.com/maxb1906/aplomb/internal/rules"
)

// reportFlags sont communes à audit et evaluate.
type reportFlags struct {
	out, format, reportLang, profile string
	noOpen                           bool
}

func (e *env) addReportFlags(fs *flag.FlagSet) *reportFlags {
	f := &reportFlags{}
	fs.StringVar(&f.out, "out", "", "")
	fs.StringVar(&f.format, "format", "", "")
	fs.StringVar(&f.reportLang, "report-lang", "", "")
	fs.StringVar(&f.profile, "profile", "", "")
	fs.BoolVar(&f.noOpen, "no-open", false, "")
	return f
}

// parseProfile accepte les noms français et anglais.
func parseProfile(p string) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(p)) {
	case "":
		return "", true
	case "poste", "workstation":
		return model.RoleWorkstation, true
	case "serveur", "server":
		return model.RoleServer, true
	case "dc", "controleur", "contrôleur":
		return model.RoleDC, true
	}
	return "", false
}

func cmdAudit(e *env, args []string) int {
	fs := e.newFlags("audit")
	f := e.addReportFlags(fs)
	if code, ok := e.parse(fs, args); !ok {
		return code
	}
	fmt.Fprintln(e.stdout, e.T("audit.start"))
	snap, err := collect.Collect(version, func(section string) {
		fmt.Fprintln(e.stdout, "  · "+e.T("section."+section))
	})
	if errors.Is(err, collect.ErrNotWindows) {
		fmt.Fprintln(e.stderr, e.T("audit.not_windows"))
		return 2
	}
	if err != nil {
		return e.fail(err)
	}
	return e.produce(snap, f)
}

func cmdEvaluate(e *env, args []string) int {
	fs := e.newFlags("evaluate")
	input := fs.String("input", "", "")
	f := e.addReportFlags(fs)
	if code, ok := e.parse(fs, args); !ok {
		return code
	}
	if *input == "" {
		fmt.Fprintln(e.stderr, e.T("evaluate.need_input"))
		return 2
	}
	snap, err := model.Load(*input)
	if err != nil {
		return e.fail(err)
	}
	return e.produce(snap, f)
}

func cmdCollect(e *env, args []string) int {
	fs := e.newFlags("collect")
	out := fs.String("out", "", "")
	if code, ok := e.parse(fs, args); !ok {
		return code
	}
	snap, err := collect.Collect(version, nil)
	if errors.Is(err, collect.ErrNotWindows) {
		fmt.Fprintln(e.stderr, e.T("audit.not_windows"))
		return 2
	}
	if err != nil {
		return e.fail(err)
	}
	w := e.stdout
	if *out != "" {
		file, err := os.Create(*out)
		if err != nil {
			return e.fail(err)
		}
		defer file.Close()
		w = file
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(snap); err != nil {
		return e.fail(err)
	}
	if *out != "" {
		fmt.Fprintln(e.stderr, e.T("collect.written", "path", *out))
	}
	return 0
}

// produce évalue un snapshot, écrit les rapports et affiche le résumé.
func (e *env) produce(snap *model.Snapshot, f *reportFlags) int {
	cfg := e.cfg
	cat, err := rules.Default()
	if err != nil {
		return e.fail(err)
	}
	profileArg := f.profile
	if profileArg == "" {
		profileArg = cfg.Profile
	}
	profile, ok := parseProfile(profileArg)
	if !ok {
		fmt.Fprintln(e.stderr, e.T("audit.bad_profile", "profile", profileArg))
		return 2
	}
	results, err := cat.Evaluate(snap, rules.Options{Profile: profile, Accepted: cfg.Accepted()})
	if err != nil {
		return e.fail(err)
	}

	lang := f.reportLang
	if lang == "" {
		lang = cfg.ReportLang
	}
	if lang == "" {
		lang = e.tr.Lang()
	}
	if !e.bundle.Has(lang) {
		fmt.Fprintln(e.stderr, e.T("cli.unknown_lang", "lang", lang, "available", strings.Join(e.bundle.Languages(), ", ")))
		return 2
	}
	effProfile := profile
	if effProfile == "" {
		effProfile = snap.Host.Role
	}
	rep := report.Build(snap, results, cat, report.Meta{Version: version, Lang: lang, Profile: effProfile, Technician: cfg.Technician, Company: cfg.Company})

	formats := report.Formats
	if f.format != "" {
		formats = strings.Split(f.format, ",")
	} else if len(cfg.Formats) > 0 {
		formats = cfg.Formats
	}
	for _, fm := range formats {
		if !validFormat(strings.TrimSpace(fm)) {
			fmt.Fprintln(e.stderr, e.T("audit.bad_format", "format", fm))
			return 2
		}
	}
	base := f.out
	if base == "" {
		base = filepath.Join(e.dataDir(), "rapports")
	}
	dir := report.Dir(base, snap.Host.Name)
	opts := report.Options{Translator: e.bundle.Translator(lang), Catalog: cat, LogoPath: cfg.LogoPath(e.dataDir())}
	paths, err := report.Write(dir, report.BaseName(snap.CollectedAt), formats, rep, opts)
	if err != nil {
		return e.fail(err)
	}

	s := rep.Score
	fmt.Fprintln(e.stdout)
	fmt.Fprintln(e.stdout, e.T("audit.score", "score", fmt.Sprint(s.Score), "grade", s.Grade, "coverage", fmt.Sprint(s.Coverage)))
	fmt.Fprintln(e.stdout, e.T("audit.counts", "critical", fmt.Sprint(s.Counts.Critical), "warning", fmt.Sprint(s.Counts.Warning), "info", fmt.Sprint(s.Counts.Info), "not_checked", fmt.Sprint(s.Counts.NotChecked)))
	if !snap.Host.Elevated && s.Counts.NotChecked > 0 {
		fmt.Fprintln(e.stdout, e.T("audit.hint_admin"))
	}
	fmt.Fprintln(e.stdout, e.T("audit.written"))
	for _, p := range paths {
		fmt.Fprintln(e.stdout, "  "+p)
	}
	fmt.Fprintln(e.stdout, e.T("audit.confidential"))
	if !f.noOpen {
		for _, p := range paths {
			if strings.HasSuffix(p, ".html") {
				if err := report.Open(p); err != nil {
					fmt.Fprintln(e.stderr, e.T("cli.error", "error", err.Error()))
				}
			}
		}
	}
	return 0
}

func validFormat(f string) bool {
	for _, x := range report.Formats {
		if strings.EqualFold(f, x) {
			return true
		}
	}
	return false
}

// dataDir renvoie le dossier aplomb-data : --data, APLOMB_DATA, sinon à côté de l'exe.
func (e *env) dataDir() string {
	if e.data != "" {
		return e.data
	}
	if d := os.Getenv("APLOMB_DATA"); d != "" {
		return d
	}
	exe, err := os.Executable()
	if err != nil {
		return "aplomb-data"
	}
	if r, err := filepath.EvalSymlinks(exe); err == nil {
		exe = r
	}
	return filepath.Join(filepath.Dir(exe), "aplomb-data")
}

// loadConfig lit config.yaml (et crée le modèle commenté au premier lancement).
func (e *env) loadConfig() {
	e.cfgLoaded = true
	dir := e.dataDir()
	_ = config.WriteTemplate(dir)
	cfg, err := config.Load(dir)
	if err != nil {
		fmt.Fprintln(e.stderr, e.T("cli.error", "error", err.Error()))
	}
	e.cfg = cfg
}
