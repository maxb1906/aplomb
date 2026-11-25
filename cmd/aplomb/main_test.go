package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func runCLI(t *testing.T, args ...string) (int, string) {
	t.Helper()
	var out, errOut bytes.Buffer
	code := run(context.Background(), args, &out, &errOut)
	return code, out.String() + errOut.String()
}

func fixturePath(name string) string {
	return filepath.Join("..", "..", "testdata", "snapshots", name+".json")
}

func TestRun(t *testing.T) {
	data := t.TempDir()
	cases := []struct {
		args     []string
		code     int
		contains string
	}{
		{[]string{"--lang", "fr", "hello"}, 0, "Bonjour depuis Aplomb"},
		{[]string{"--lang", "en", "hello"}, 0, "Hello from Aplomb"},
		{[]string{"version"}, 0, "dev"},
		{[]string{"--lang", "en", "nope"}, 2, "Unknown command: nope"},
		{[]string{"--lang", "xx", "hello"}, 2, "xx"},
		{[]string{"--lang", "en", "-h"}, 0, "Usage: aplomb"},
		{[]string{"--lang", "fr", "help"}, 0, "Commandes"},
		{[]string{"--bogus"}, 2, "bogus"},
		{[]string{"--lang", "fr", "rules"}, 0, "SYS-012"},
		{[]string{"--lang", "en", "--data", data, "evaluate"}, 2, "--input"},
		{[]string{"--lang", "en", "--data", data, "evaluate", "--input", fixturePath("healthy-workstation"), "--profile", "nope"}, 2, "Unknown profile"},
		{[]string{"--lang", "en", "--data", data, "evaluate", "--input", fixturePath("healthy-workstation"), "--format", "pdf"}, 2, "Unknown format"},
	}
	if runtime.GOOS != "windows" {
		cases = append(cases, struct {
			args     []string
			code     int
			contains string
		}{[]string{"--lang", "en", "--data", data}, 2, "only possible on Windows"})
	}
	for _, c := range cases {
		code, all := runCLI(t, c.args...)
		if code != c.code {
			t.Errorf("%v : code %d, attendu %d (%s)", c.args, code, c.code, all)
		}
		if !strings.Contains(all, c.contains) {
			t.Errorf("%v : sortie %q ne contient pas %q", c.args, all, c.contains)
		}
	}
}

// evaluate produit les rapports dans <data>/rapports/<MACHINE>/.
func TestEvaluateWritesReports(t *testing.T) {
	data := t.TempDir()
	code, out := runCLI(t, "--lang", "fr", "--data", data, "evaluate", "--input", fixturePath("vulnerable-workstation"), "--no-open")
	if code != 0 {
		t.Fatalf("code %d : %s", code, out)
	}
	if !strings.Contains(out, "Score :") {
		t.Errorf("résumé absent : %s", out)
	}
	files, _ := filepath.Glob(filepath.Join(data, "rapports", "PC-ACCUEIL-01", "*"))
	exts := map[string]bool{}
	for _, f := range files {
		exts[filepath.Ext(f)] = true
	}
	for _, want := range []string{".html", ".md", ".json", ".ps1"} {
		if !exts[want] {
			t.Errorf("fichier %s absent (%v)", want, files)
		}
	}
	if _, err := os.Stat(filepath.Join(data, "config.yaml")); err != nil {
		t.Error("config.yaml non créé")
	}
	// Le rapport JSON peut être réévalué.
	jsons, _ := filepath.Glob(filepath.Join(data, "rapports", "PC-ACCUEIL-01", "*.json"))
	var rep map[string]json.RawMessage
	b, _ := os.ReadFile(jsons[0])
	if err := json.Unmarshal(b, &rep); err != nil || rep["meta"] == nil || rep["checks"] == nil || rep["score"] == nil {
		t.Fatalf("rapport JSON : %v", err)
	}
	if code, out := runCLI(t, "--lang", "en", "--data", data, "evaluate", "--input", jsons[0], "--out", t.TempDir(), "--format", "md", "--report-lang", "en", "--no-open"); code != 0 {
		t.Errorf("réévaluation : %d %s", code, out)
	}
}

// Chaque commande et chaque option doit avoir sa traduction.
func TestHelpIsTranslated(t *testing.T) {
	for _, lang := range []string{"fr", "en"} {
		for _, c := range order {
			if _, ok := commands[c]; !ok {
				t.Errorf("commande %q dans order mais pas enregistrée", c)
			}
			_, out := runCLI(t, "--lang", lang, "--data", t.TempDir(), c, "-h")
			for _, line := range strings.Split(out, "\n") {
				if strings.Contains(line, "flag.") || strings.Contains(line, "cmd.") {
					t.Errorf("%s %s : clé non traduite : %q", lang, c, line)
				}
			}
		}
	}
}

func TestParseProfile(t *testing.T) {
	for in, want := range map[string]string{"poste": "workstation", "Serveur": "server", "server": "server", "dc": "dc", "": ""} {
		if got, ok := parseProfile(in); !ok || got != want {
			t.Errorf("%q → %q", in, got)
		}
	}
}
