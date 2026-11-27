package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/maxb1906/aplomb/internal/app"
	"github.com/maxb1906/aplomb/internal/collect"
	"github.com/maxb1906/aplomb/internal/model"
	"github.com/maxb1906/aplomb/internal/report"
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

func cmdAudit(e *env, args []string) int {
	fs := e.newFlags("audit")
	f := e.addReportFlags(fs)
	if code, ok := e.parse(fs, args); !ok {
		return code
	}
	fmt.Fprintln(e.stdout, e.T("audit.start"))
	if !collect.Elevated() {
		fmt.Fprintln(e.stdout, e.T("audit.not_elevated"))
	}
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
	req := app.Request{Version: version, Profile: f.profile, ReportLang: f.reportLang, UILang: e.tr.Lang(), OutBase: f.out, DataDir: e.dataDir()}
	if f.format != "" {
		req.Formats = strings.Split(f.format, ",")
	}
	out, err := app.Produce(snap, e.cfg, e.bundle, req)
	var ie *app.InputError
	if errors.As(err, &ie) {
		fmt.Fprintln(e.stderr, ie.Message(e.tr))
		return 2
	}
	if err != nil {
		return e.fail(err)
	}

	s := out.Report.Score
	fmt.Fprintln(e.stdout)
	fmt.Fprintln(e.stdout, e.T("audit.score", "score", fmt.Sprint(s.Score), "grade", s.Grade, "coverage", fmt.Sprint(s.Coverage)))
	fmt.Fprintln(e.stdout, e.T("audit.counts", "critical", fmt.Sprint(s.Counts.Critical), "warning", fmt.Sprint(s.Counts.Warning), "info", fmt.Sprint(s.Counts.Info), "not_checked", fmt.Sprint(s.Counts.NotChecked)))
	if !snap.Host.Elevated && s.Counts.NotChecked > 0 {
		fmt.Fprintln(e.stdout, e.T("audit.hint_admin"))
	}
	fmt.Fprintln(e.stdout, e.T("audit.written"))
	for _, p := range out.Paths {
		fmt.Fprintln(e.stdout, "  "+p)
	}
	fmt.Fprintln(e.stdout, e.T("audit.confidential"))
	if p := out.HTMLPath(); p != "" && !f.noOpen {
		if err := report.Open(p); err != nil {
			fmt.Fprintln(e.stderr, e.T("cli.error", "error", err.Error()))
		}
	}
	return 0
}

// dataDir renvoie le dossier aplomb-data : --data, APLOMB_DATA, sinon à côté de l'exe.
func (e *env) dataDir() string { return app.DataDir(e.data) }

// loadConfig lit config.yaml (et crée le modèle commenté au premier lancement).
func (e *env) loadConfig() {
	e.cfgLoaded = true
	cfg, err := app.LoadConfig(e.dataDir())
	if err != nil {
		fmt.Fprintln(e.stderr, e.T("cli.error", "error", err.Error()))
	}
	e.cfg = cfg
}
