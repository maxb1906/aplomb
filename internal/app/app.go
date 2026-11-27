// Package app enchaîne les étapes d'un audit — configuration, évaluation,
// écriture des rapports, historique — pour la ligne de commande et pour
// l'interface graphique, qui partagent ainsi exactement le même comportement.
package app

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/maxb1906/aplomb/internal/config"
	"github.com/maxb1906/aplomb/internal/i18n"
	"github.com/maxb1906/aplomb/internal/model"
	"github.com/maxb1906/aplomb/internal/report"
	"github.com/maxb1906/aplomb/internal/rules"
	"gopkg.in/yaml.v3"
)

// InputError est une option invalide ; Key et Pairs donnent son message traduit.
type InputError struct {
	Key   string
	Pairs []string
}

func (e *InputError) Error() string { return e.Key + " " + strings.Join(e.Pairs, " ") }

// Message traduit l'erreur.
func (e *InputError) Message(tr *i18n.Translator) string { return tr.T(e.Key, e.Pairs...) }

// DataDir renvoie le dossier aplomb-data : override, APLOMB_DATA, sinon à côté de l'exe.
func DataDir(override string) string {
	if override != "" {
		return override
	}
	if d := os.Getenv("APLOMB_DATA"); d != "" {
		return d
	}
	exe, err := os.Executable()
	if err != nil {
		return "aplomb-data"
	}
	if r, err := filepath.EvalSymlinks(exe); err == nil {
		exe = r
	}
	return filepath.Join(filepath.Dir(exe), "aplomb-data")
}

// ReportsDir est le dossier racine des rapports dans le dossier de données.
func ReportsDir(dataDir string) string { return filepath.Join(dataDir, "rapports") }

// ParseProfile accepte les noms français et anglais ("" = détection automatique).
func ParseProfile(p string) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(p)) {
	case "":
		return "", true
	case "poste", "workstation":
		return model.RoleWorkstation, true
	case "serveur", "server":
		return model.RoleServer, true
	case "dc", "controleur", "contrôleur":
		return model.RoleDC, true
	}
	return "", false
}

// LoadConfig lit config.yaml et crée le modèle commenté au premier lancement.
// En cas d'erreur de lecture, la configuration renvoyée est vide mais utilisable.
func LoadConfig(dataDir string) (*config.Config, error) {
	_ = config.WriteTemplate(dataDir)
	return config.Load(dataDir)
}

// SaveConfig valide puis réécrit config.yaml ; header est un commentaire de tête.
func SaveConfig(dataDir string, c *config.Config, bundle *i18n.Bundle, header string) (string, error) {
	if c.Lang != "" && !bundle.Has(c.Lang) || c.ReportLang != "" && !bundle.Has(c.ReportLang) {
		return "", &InputError{Key: "config.bad_lang"}
	}
	if _, ok := ParseProfile(c.Profile); !ok {
		return "", &InputError{Key: "audit.bad_profile", Pairs: []string{"profile", c.Profile}}
	}
	for _, f := range c.Formats {
		if !ValidFormat(f) {
			return "", &InputError{Key: "audit.bad_format", Pairs: []string{"format", f}}
		}
	}
	data, err := yaml.Marshal(c)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		return "", err
	}
	path := filepath.Join(dataDir, config.FileName)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append([]byte(header+"\n"), data...), 0o644); err != nil {
		return "", err
	}
	return path, os.Rename(tmp, path)
}

// ValidFormat indique un format de rapport connu.
func ValidFormat(f string) bool {
	for _, x := range report.Formats {
		if strings.EqualFold(strings.TrimSpace(f), x) {
			return true
		}
	}
	return false
}

// Request règle la production d'un rapport ; les champs vides prennent la
// valeur de la configuration, puis la valeur par défaut.
type Request struct {
	Version    string
	Profile    string   // poste | serveur | dc, en français ou en anglais
	ReportLang string   // langue des fichiers
	UILang     string   // langue par défaut du rapport si rien d'autre n'est précisé
	Formats    []string // html, md, json, ps1
	OutBase    string   // dossier racine des rapports (défaut : <data>/rapports)
	DataDir    string
}

// Output est le résultat d'une production de rapport.
type Output struct {
	Report *report.Report
	Dir    string
	Paths  []string
}

// HTMLPath renvoie le chemin du rapport HTML produit ("" si absent).
func (o *Output) HTMLPath() string {
	for _, p := range o.Paths {
		if strings.HasSuffix(p, ".html") {
			return p
		}
	}
	return ""
}

// Produce évalue un snapshot selon la configuration et écrit les rapports.
// Les fichiers portent la date de collecte : réévaluer le même snapshot
// (après avoir accepté un risque, par exemple) remplace ses rapports.
func Produce(snap *model.Snapshot, cfg *config.Config, bundle *i18n.Bundle, req Request) (*Output, error) {
	cat, err := rules.Default()
	if err != nil {
		return nil, err
	}
	profileArg := req.Profile
	if profileArg == "" {
		profileArg = cfg.Profile
	}
	profile, ok := ParseProfile(profileArg)
	if !ok {
		return nil, &InputError{Key: "audit.bad_profile", Pairs: []string{"profile", profileArg}}
	}
	results, err := cat.Evaluate(snap, rules.Options{Profile: profile, Accepted: cfg.Accepted()})
	if err != nil {
		return nil, err
	}
	lang := firstNonEmpty(req.ReportLang, cfg.ReportLang, req.UILang)
	if !bundle.Has(lang) {
		return nil, &InputError{Key: "cli.unknown_lang", Pairs: []string{"lang", lang, "available", strings.Join(bundle.Languages(), ", ")}}
	}
	effProfile := profile
	if effProfile == "" {
		effProfile = snap.Host.Role
	}
	rep := report.Build(snap, results, cat, report.Meta{Version: req.Version, Lang: lang, Profile: effProfile, Technician: cfg.Technician, Company: cfg.Company})

	formats := report.Formats
	if len(req.Formats) > 0 {
		formats = req.Formats
	} else if len(cfg.Formats) > 0 {
		formats = cfg.Formats
	}
	for _, f := range formats {
		if !ValidFormat(f) {
			return nil, &InputError{Key: "audit.bad_format", Pairs: []string{"format", f}}
		}
	}
	base := req.OutBase
	if base == "" {
		base = ReportsDir(req.DataDir)
	}
	dir := report.Dir(base, snap.Host.Name)
	opts := report.Options{Translator: bundle.Translator(lang), Catalog: cat, LogoPath: cfg.LogoPath(req.DataDir)}
	paths, err := report.Write(dir, report.BaseName(snap.CollectedAt), formats, rep, opts)
	if err != nil {
		return nil, err
	}
	return &Output{Report: rep, Dir: dir, Paths: paths}, nil
}

func firstNonEmpty(ss ...string) string {
	for _, s := range ss {
		if s != "" {
			return s
		}
	}
	return ""
}
