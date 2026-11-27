package main

import (
	"errors"
	"flag"
	"fmt"
	"path/filepath"

	"gopkg.in/yaml.v3"

	"github.com/maxb1906/aplomb/internal/app"
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
	path := filepath.Join(dir, config.FileName)
	if changed {
		path, err := app.SaveConfig(dir, c, e.bundle, e.T("config.header"))
		var ie *app.InputError
		if errors.As(err, &ie) {
			fmt.Fprintln(e.stderr, ie.Message(e.tr))
			return 2
		}
		if err != nil {
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
