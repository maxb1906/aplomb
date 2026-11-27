package gui

import (
	"errors"
	"io/fs"
	"time"
)

// Erreurs de lancement : l'appelant se replie alors sur la ligne de commande.
var (
	ErrUnsupported = errors.New("graphical interface only available on Windows")
	ErrNoWebView2  = errors.New("WebView2 runtime not installed")
	ErrNoFrontend  = errors.New("graphical interface not built")
)

// RunOptions règle la fenêtre.
type RunOptions struct {
	Assets fs.FS
	Title  string
	// Args sont repris pour relancer l'exe en administrateur (--data, --lang).
	Args []string
	// Smoke ferme la fenêtre dès que l'interface est prête (test de lancement) ;
	// Run échoue si elle ne l'est pas avant SmokeTimeout.
	Smoke        bool
	SmokeTimeout time.Duration
}

// EventReady est émis par le frontend une fois l'interface initialisée.
const EventReady = "gui:ready"
