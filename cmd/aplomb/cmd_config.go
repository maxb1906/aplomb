package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"

	"github.com/maxb1906/aplomb/internal/config"
)

// cmdConfig affiche la configuration, ou la modifie avec les options données.
func cmdConfig(e *env, args []string) int {
	fs := e.newFlags("config")
	tech := fs.String("technician", "", "")
	company := fs.String("company", "", "")
	logo := fs.String("logo", "", "")
	lang := fs.String("lang", "", "")
	rlang := fs.String("report-lang", "", "")
	profile := fs.String("profile", "", "")
	if code, ok := e.parse(fs, args); !ok {
		return code
	}
	dir := e.dataDir()
	if !e.cfgLoaded {
		e.loadConfig()
	}
	c := e.cfg
	changed := false
	set := func(name string, dst *string, v string) {
		fs.Visit(func(f *flag.Flag) {
			if f.Name == name {
				*dst, changed = v, true
			}
		})
	}
	set("technician", &c.Technician, *tech)
	set("company", &c.Company, *company)
	set("logo", &c.Logo, *logo)
	set("lang", &c.Lang, *lang)
	set("report-lang", &c.ReportLang, *rlang)
	set("profile", &c.Profile, *profile)
	if c.Lang != "" && !e.bundle.Has(c.Lang) || c.ReportLang != "" && !e.bundle.Has(c.ReportLang) {
		fmt.Fprintln(e.stderr, e.T("config.bad_lang"))
		return 2
	}
	if _, ok := parseProfile(c.Profile); !ok {
		fmt.Fprintln(e.stderr, e.T("audit.bad_profile", "profile", c.Profile))
		return 2
	}
	path := filepath.Join(dir, config.FileName)
	if changed {
		data, err := yaml.Marshal(c)
		if err != nil {
			return e.fail(err)
		}
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return e.fail(err)
		}
		if err := os.WriteFile(path, append([]byte(e.T("config.header")+"\n"), data...), 0o644); err != nil {
			return e.fail(err)
		}
		fmt.Fprintln(e.stdout, e.T("config.saved", "path", path))
		return 0
	}
	fmt.Fprintln(e.stdout, e.T("config.path", "path", path))
	out, _ := yaml.Marshal(c)
	fmt.Fprint(e.stdout, string(out))
	return 0
}
