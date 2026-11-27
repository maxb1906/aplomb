package main

import (
	"errors"
	"fmt"
	"path/filepath"
	"time"

	"github.com/maxb1906/aplomb/frontend"
	"github.com/maxb1906/aplomb/internal/gui"
)

// guiShown : la fenêtre a été ouverte, la console a pu être libérée.
var guiShown bool

// cmdGui ouvre l'interface graphique. Si elle ne peut pas s'ouvrir (WebView2
// absent, notamment sur Windows Server 2016 à 2022), l'audit se fait en console.
func cmdGui(e *env, args []string) int {
	fs := e.newFlags("gui")
	smoke := fs.Bool("smoke", false, "")
	if code, ok := e.parse(fs, args); !ok {
		return code
	}
	assets := frontend.Dist()
	if err := gui.Available(assets); err != nil {
		if *smoke {
			return e.fail(err)
		}
		switch {
		case errors.Is(err, gui.ErrNoWebView2):
			fmt.Fprintln(e.stdout, e.T("gui.fallback.webview2"))
		case errors.Is(err, gui.ErrNoFrontend):
			fmt.Fprintln(e.stdout, e.T("gui.fallback.frontend"))
		}
		return cmdAudit(e, nil)
	}
	if !e.cfgLoaded {
		e.loadConfig()
	}
	dir := absPath(e.dataDir())
	a := gui.New(version, dir, e.tr.Lang(), e.bundle)
	if launchedAlone() && !*smoke {
		hideConsole()
		guiShown = true
	}
	err := gui.Run(a, gui.RunOptions{
		Assets: assets,
		Title:  "Aplomb",
		Args:   []string{"--data", dir, "--lang", e.tr.Lang(), "gui"},
		Smoke:  *smoke, SmokeTimeout: 90 * time.Second,
	})
	if err != nil {
		return e.fail(err)
	}
	return 0
}

// absPath rend un chemin absolu (la relance en administrateur change de dossier courant).
func absPath(p string) string {
	if a, err := filepath.Abs(p); err == nil {
		return a
	}
	return p
}
