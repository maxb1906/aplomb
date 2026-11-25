// Package report produit les rapports HTML, Markdown, JSON et le script de
// remédiation à partir des résultats d'un audit.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/maxb1906/aplomb/internal/model"
	"github.com/maxb1906/aplomb/internal/rules"
	"github.com/maxb1906/aplomb/internal/score"
)

// Schema est la version du format JSON du rapport.
const Schema = 1

// Meta décrit l'audit (§ 6).
type Meta struct {
	Tool        string    `json:"tool"`
	Version     string    `json:"version"`
	Schema      int       `json:"schema"`
	GeneratedAt time.Time `json:"generated_at"`
	CollectedAt time.Time `json:"collected_at"`
	DurationMS  int64     `json:"duration_ms"`
	Lang        string    `json:"lang"`
	Profile     string    `json:"profile"`
	Elevated    bool      `json:"elevated"`
	Technician  string    `json:"technician,omitempty"`
	Company     string    `json:"company,omitempty"`
}

// Report est le contenu complet d'un rapport ; c'est aussi le JSON produit.
type Report struct {
	Meta       Meta            `json:"meta"`
	Host       model.Host      `json:"host"`
	Checks     []rules.Result  `json:"checks"`
	Score      score.Score     `json:"score"`
	Collection *model.Snapshot `json:"collection"`
}

// Build assemble un rapport.
func Build(s *model.Snapshot, results []rules.Result, cat *rules.Catalog, m Meta) *Report {
	m.Tool, m.Schema = "aplomb", Schema
	m.CollectedAt, m.DurationMS, m.Elevated = s.CollectedAt, s.DurationMS, s.Host.Elevated
	if m.GeneratedAt.IsZero() {
		m.GeneratedAt = time.Now().UTC().Truncate(time.Second)
	}
	return &Report{Meta: m, Host: s.Host, Checks: results, Score: score.Compute(results, cat), Collection: s}
}

// JSON écrit le rapport en JSON indenté.
func JSON(w io.Writer, r *Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

// Formats connus, dans l'ordre de génération.
var Formats = []string{"html", "md", "json", "ps1"}

var unsafeName = regexp.MustCompile(`[^A-Za-z0-9._-]+`)

// Dir renvoie le dossier des rapports d'une machine : <base>/<NOM-MACHINE>.
func Dir(base, hostName string) string {
	name := strings.Trim(unsafeName.ReplaceAllString(hostName, "_"), "._")
	if name == "" {
		name = "machine"
	}
	return filepath.Join(base, name)
}

// BaseName renvoie le nom de fichier (sans extension) d'un rapport : AAAA-MM-JJ_HHMM.
func BaseName(t time.Time) string { return t.Local().Format("2006-01-02_1504") }

// Write génère les formats demandés dans dir et renvoie les chemins créés.
func Write(dir, base string, formats []string, r *Report, o Options) ([]string, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	var paths []string
	for _, f := range Formats {
		if !contains(formats, f) {
			continue
		}
		p := filepath.Join(dir, base+"."+f)
		if f == "ps1" {
			p = filepath.Join(dir, base+"_remediation.ps1")
		}
		if err := writeFile(p, func(w io.Writer) error {
			switch f {
			case "html":
				return HTML(w, r, o)
			case "md":
				return Markdown(w, r, o)
			case "json":
				return JSON(w, r)
			default:
				return Script(w, r, o)
			}
		}); err != nil {
			return paths, fmt.Errorf("%s : %w", p, err)
		}
		paths = append(paths, p)
	}
	return paths, nil
}

func writeFile(p string, fn func(io.Writer) error) error {
	tmp := p + ".tmp"
	f, err := os.Create(tmp)
	if err != nil {
		return err
	}
	if err := fn(f); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, p)
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if strings.EqualFold(strings.TrimSpace(x), s) {
			return true
		}
	}
	return false
}
