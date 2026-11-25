package main

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

func runCLI(t *testing.T, args ...string) (int, string) {
	t.Helper()
	var out, errOut bytes.Buffer
	code := run(context.Background(), args, &out, &errOut)
	return code, out.String() + errOut.String()
}

func TestRun(t *testing.T) {
	cases := []struct {
		args     []string
		code     int
		contains string
	}{
		{[]string{"--lang", "fr", "hello"}, 0, "Bonjour depuis Aplomb"},
		{[]string{"--lang", "en", "hello"}, 0, "Hello from Aplomb"},
		{[]string{"--lang", "en"}, 0, "Hello from Aplomb"}, // sans commande
		{[]string{"version"}, 0, "dev"},
		{[]string{"--lang", "en", "nope"}, 2, "Unknown command: nope"},
		{[]string{"--lang", "xx"}, 2, "xx"},
		{[]string{"--lang", "en", "-h"}, 0, "Usage: aplomb"},
		{[]string{"--lang", "fr", "help"}, 0, "Commandes"},
		{[]string{"--bogus"}, 2, "bogus"},
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

// Chaque commande listée dans l'aide doit exister et être traduite.
func TestHelpIsTranslated(t *testing.T) {
	for _, lang := range []string{"fr", "en"} {
		_, out := runCLI(t, "--lang", lang, "help")
		for _, c := range order {
			if _, ok := commands[c]; !ok {
				t.Errorf("commande %q dans order mais pas enregistrée", c)
			}
		}
		if strings.Contains(out, "cmd.") {
			t.Errorf("%s : clé non traduite dans l'aide :\n%s", lang, out)
		}
	}
}
