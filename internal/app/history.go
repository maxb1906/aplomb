package app

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/maxb1906/aplomb/internal/model"
	"github.com/maxb1906/aplomb/internal/report"
	"github.com/maxb1906/aplomb/internal/score"
)

// Entry résume un rapport JSON déjà produit (historique).
type Entry struct {
	Path        string    `json:"path"`
	Host        string    `json:"host"`
	OS          string    `json:"os"`
	Role        string    `json:"role"`
	CollectedAt time.Time `json:"collected_at"`
	Version     string    `json:"version"`
	Elevated    bool      `json:"elevated"`
	Score       int       `json:"score"`
	Grade       string    `json:"grade"`
	Coverage    int       `json:"coverage"`
	Critical    int       `json:"critical"`
	Warning     int       `json:"warning"`
	Info        int       `json:"info"`
	HasHTML     bool      `json:"has_html"`
}

// History liste les rapports JSON de base/<MACHINE>/*.json, du plus récent au
// plus ancien. Les fichiers illisibles ou d'un autre format sont ignorés.
func History(base string) ([]Entry, error) {
	files, err := filepath.Glob(filepath.Join(base, "*", "*.json"))
	if err != nil {
		return nil, err
	}
	out := []Entry{}
	for _, f := range files {
		rep, err := readHeader(f)
		if err != nil || rep.Meta.Tool != "aplomb" {
			continue
		}
		s := rep.Score
		_, herr := os.Stat(strings.TrimSuffix(f, ".json") + ".html")
		out = append(out, Entry{
			Path: f, Host: rep.Host.Name, OS: strings.TrimSpace(rep.Host.OS + " " + rep.Host.DisplayVersion), Role: rep.Meta.Profile,
			CollectedAt: rep.Meta.CollectedAt, Version: rep.Meta.Version, Elevated: rep.Meta.Elevated,
			Score: s.Score, Grade: s.Grade, Coverage: s.Coverage,
			Critical: s.Counts.Critical, Warning: s.Counts.Warning, Info: s.Counts.Info, HasHTML: herr == nil,
		})
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].CollectedAt.After(out[j].CollectedAt) })
	return out, nil
}

// readHeader lit un rapport sans décoder sa collecte brute.
func readHeader(path string) (*report.Report, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var r struct {
		Meta  report.Meta `json:"meta"`
		Host  model.Host  `json:"host"`
		Score score.Score `json:"score"`
	}
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, err
	}
	return &report.Report{Meta: r.Meta, Host: r.Host, Score: r.Score}, nil
}

// ErrNotReport : le fichier JSON n'est pas un rapport Aplomb.
var ErrNotReport = errors.New("not an aplomb report")

// LoadReport lit un rapport JSON complet, collecte brute comprise.
func LoadReport(path string) (*report.Report, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var rep report.Report
	if err := json.Unmarshal(data, &rep); err != nil {
		return nil, err
	}
	if rep.Meta.Tool != "aplomb" {
		return nil, ErrNotReport
	}
	return &rep, nil
}
