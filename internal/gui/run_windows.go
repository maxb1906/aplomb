//go:build windows

package gui

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/wailsapp/go-webview2/webviewloader"
	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/assetserver"
	"github.com/wailsapp/wails/v2/pkg/options/windows"
	wruntime "github.com/wailsapp/wails/v2/pkg/runtime"
	xwindows "golang.org/x/sys/windows"
)

// minWebView2 est la version minimale du runtime WebView2 exigée par Wails.
const minWebView2 = "94.0.992.31"

// WebView2Version renvoie la version du runtime WebView2 installée ("" si absent).
func WebView2Version() string {
	v, err := webviewloader.GetAvailableCoreWebView2BrowserVersionString("")
	if err != nil || v == "" {
		return ""
	}
	if c, err := webviewloader.CompareBrowserVersions(v, minWebView2); err != nil || c < 0 {
		return ""
	}
	return v
}

// Available indique si la fenêtre peut s'ouvrir (WebView2 et interface compilée).
func Available(assets fs.FS) error {
	if WebView2Version() == "" {
		return ErrNoWebView2
	}
	if _, err := fs.Stat(assets, "index.html"); err != nil {
		return ErrNoFrontend
	}
	return nil
}

// Run ouvre la fenêtre et rend la main à sa fermeture.
func Run(a *App, o RunOptions) error {
	if err := Available(o.Assets); err != nil {
		return err
	}
	sh := &shell{args: o.Args}
	a.SetShell(sh)
	var smokeErr error
	err := wails.Run(&options.App{
		Title:     o.Title,
		Width:     1240,
		Height:    840,
		MinWidth:  960,
		MinHeight: 640,
		AssetServer: &assetserver.Options{
			Assets: o.Assets,
		},
		BackgroundColour: &options.RGBA{R: 246, G: 247, B: 249, A: 255},
		OnStartup: func(ctx context.Context) {
			sh.ctx = ctx
			if o.Smoke {
				timeout := o.SmokeTimeout
				if timeout == 0 {
					timeout = time.Minute
				}
				ready := make(chan struct{}, 1)
				wruntime.EventsOnce(ctx, EventReady, func(...any) { ready <- struct{}{} })
				go func() {
					select {
					case <-ready:
					case <-time.After(timeout):
						smokeErr = errors.New("smoke test: interface not ready")
					}
					wruntime.Quit(ctx)
				}()
			}
		},
		Bind: []any{a},
		Windows: &windows.Options{
			Theme:               windows.SystemDefault,
			WebviewUserDataPath: webviewDataDir(a.DataDir),
		},
	})
	if err != nil {
		return err
	}
	return smokeErr
}

// webviewDataDir place le cache de WebView2 dans aplomb-data (seul dossier
// qu'Aplomb écrit) ; à défaut (support en lecture seule), dans le dossier temporaire.
func webviewDataDir(dataDir string) string {
	d := filepath.Join(dataDir, "webview2")
	if err := os.MkdirAll(d, 0o755); err == nil {
		return d
	}
	return filepath.Join(os.TempDir(), "aplomb-webview2")
}

// shell implémente Shell avec le runtime Wails et l'API Windows.
type shell struct {
	ctx  context.Context
	args []string
}

func (s *shell) Emit(event string, data any) {
	if s.ctx != nil {
		wruntime.EventsEmit(s.ctx, event, data)
	}
}

func (s *shell) Open(path string) error {
	return shellExecute("open", path, "")
}

func (s *shell) ChooseImage(title string) (string, error) {
	return wruntime.OpenFileDialog(s.ctx, wruntime.OpenDialogOptions{
		Title:   title,
		Filters: []wruntime.FileFilter{{DisplayName: "PNG, JPEG, SVG", Pattern: "*.png;*.jpg;*.jpeg;*.svg"}},
	})
}

func (s *shell) RelaunchElevated() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	return shellExecute("runas", exe, joinArgs(s.args))
}

func (s *shell) Quit() {
	if s.ctx != nil {
		wruntime.Quit(s.ctx)
	}
}

func shellExecute(verb, file, args string) error {
	v, err := syscall.UTF16PtrFromString(verb)
	if err != nil {
		return err
	}
	f, err := syscall.UTF16PtrFromString(file)
	if err != nil {
		return err
	}
	var a *uint16
	if args != "" {
		if a, err = syscall.UTF16PtrFromString(args); err != nil {
			return err
		}
	}
	return xwindows.ShellExecute(0, v, f, a, nil, xwindows.SW_SHOWNORMAL)
}

// joinArgs cite les arguments pour la ligne de commande Windows.
func joinArgs(args []string) string {
	q := make([]string, len(args))
	for i, a := range args {
		q[i] = xwindows.EscapeArg(a)
	}
	return strings.Join(q, " ")
}
