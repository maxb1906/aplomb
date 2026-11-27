// Commande guimock : génère le jeu de démonstration de l'interface
// (frontend/src/lib/mock/data.json) à partir des fixtures, pour travailler sur
// le frontend dans un navigateur (npm run dev), sans Windows.
//
//	go run ./tools/guimock
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	_ "github.com/maxb1906/aplomb/internal/checks/all"
	"github.com/maxb1906/aplomb/internal/collect"
	"github.com/maxb1906/aplomb/internal/gui"
	"github.com/maxb1906/aplomb/internal/i18n"
	"github.com/maxb1906/aplomb/internal/model"
)

var sections = []string{"host", "services", "tasks", "accounts", "bitlocker", "defender", "smb", "firewall", "system"}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	bundle, err := i18n.Default()
	if err != nil {
		return err
	}
	data, err := os.MkdirTemp("", "aplomb-guimock")
	if err != nil {
		return err
	}
	defer os.RemoveAll(data)

	out := map[string]any{}
	a := gui.New("2.0.0", data, "fr", bundle)
	for _, name := range []string{"dc", "nonadmin-server", "healthy-workstation", "vulnerable-workstation"} {
		snap, err := model.Load(filepath.Join("testdata", "snapshots", name+".json"))
		if err != nil {
			return err
		}
		a.Collect = func(string, collect.Progress) (*model.Snapshot, error) { return snap, nil }
		if _, err := a.RunAuditSync(gui.AuditOptions{}); err != nil {
			return err
		}
	}
	for _, lang := range bundle.Languages() {
		a.Strings(lang)
		in := a.Init()
		in.Sections, in.CanAudit, in.Hostname, in.Elevated = sections, true, "PC-ACCUEIL-01", true
		out["init_"+lang] = in
		out["result_"+lang] = a.Current()
		out["config_"+lang] = a.GetConfig()
	}
	h, err := a.History()
	if err != nil {
		return err
	}
	out["history"] = h
	b, err := json.MarshalIndent(out, "", " ")
	if err != nil {
		return err
	}
	dst := filepath.Join("frontend", "src", "lib", "mock", "data.json")
	fmt.Println(dst)
	return os.WriteFile(dst, b, 0o644)
}
