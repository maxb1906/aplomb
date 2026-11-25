// Package config lit aplomb-data/config.yaml, à côté de l'exécutable.
package config

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// FileName est le nom du fichier de configuration dans le dossier de données.
const FileName = "config.yaml"

// DisabledRule est une règle désactivée : son défaut apparaît comme « risque accepté ».
type DisabledRule struct {
	ID     string `yaml:"id"`
	Reason string `yaml:"reason"`
}

// Config regroupe les préférences du technicien.
type Config struct {
	Technician    string         `yaml:"technician"`
	Company       string         `yaml:"company"`
	Logo          string         `yaml:"logo"` // relatif au dossier de données, ou absolu
	Lang          string         `yaml:"lang"`
	ReportLang    string         `yaml:"report_lang"`
	Profile       string         `yaml:"profile"`
	Formats       []string       `yaml:"formats"`
	DisabledRules []DisabledRule `yaml:"disabled_rules"`
}

// Accepted renvoie les règles désactivées et leur justification.
func (c *Config) Accepted() map[string]string {
	m := map[string]string{}
	for _, d := range c.DisabledRules {
		if d.ID != "" {
			m[d.ID] = d.Reason
		}
	}
	return m
}

// LogoPath renvoie le chemin absolu du logo ("" si aucun).
func (c *Config) LogoPath(dataDir string) string {
	if c.Logo == "" || filepath.IsAbs(c.Logo) {
		return c.Logo
	}
	return filepath.Join(dataDir, c.Logo)
}

// Load lit la configuration ; un fichier absent donne une configuration vide.
func Load(dataDir string) (*Config, error) {
	c := &Config{}
	data, err := os.ReadFile(filepath.Join(dataDir, FileName))
	if errors.Is(err, fs.ErrNotExist) {
		return c, nil
	}
	if err != nil {
		return c, err
	}
	if err := yaml.Unmarshal(data, c); err != nil {
		return &Config{}, fmt.Errorf("%s : %w", FileName, err)
	}
	return c, nil
}

// Template est le fichier d'exemple créé au premier lancement.
const Template = `# Configuration d'Aplomb / Aplomb configuration
# Toutes les clés sont facultatives. / All keys are optional.

# Technicien et société affichés sur la page de garde du rapport.
technician: ""
company: ""
# Logo (PNG, JPEG ou SVG), relatif à ce dossier : logo.png
logo: ""

# Langue de l'outil et du rapport : fr | en
lang: ""
report_lang: ""

# Profil : vide = détection automatique ; poste | serveur | dc
profile: ""

# Formats générés : html, md, json, ps1
formats: [html, md, json, ps1]

# Règles désactivées (risque accepté) : la justification apparaît dans le rapport.
disabled_rules:
#  - id: SMB-003
#    reason: "Copieur ancien en SMBv1, remplacement prévu en 2027"
`

// WriteTemplate crée config.yaml s'il n'existe pas encore.
func WriteTemplate(dataDir string) error {
	p := filepath.Join(dataDir, FileName)
	if _, err := os.Stat(p); err == nil {
		return nil
	}
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		return err
	}
	return os.WriteFile(p, []byte(Template), 0o644)
}
