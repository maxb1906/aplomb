// Package config lit aplomb-data/config.yaml, à côté de l'exécutable.
package config

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// FileName est le nom du fichier de configuration dans le dossier de données.
const FileName = "config.yaml"

// DisabledRule est une règle désactivée : son défaut apparaît comme « risque accepté ».
type DisabledRule struct {
	ID     string `yaml:"id"`
	Reason string `yaml:"reason"`
}

// Issuer est l'émetteur du rapport (page de garde). Même forme que dans
// Arpent et Jalon.
type Issuer struct {
	Name    string `yaml:"name"`
	Company string `yaml:"company"`
	Contact string `yaml:"contact"` // adresse, téléphone, courriel…
	Legal   string `yaml:"legal"`   // mentions légales en pied de rapport
	Color   string `yaml:"color"`   // couleur principale, ex. #1f5f8b
	Logo    string `yaml:"logo"`    // relatif au dossier de données, ou absolu
}

// Config regroupe les préférences du technicien.
type Config struct {
	Technician    string         `yaml:"technician"`
	Lang          string         `yaml:"lang"`
	ReportLang    string         `yaml:"report_lang"`
	Issuer        Issuer         `yaml:"issuer"`
	Profile       string         `yaml:"profile"`
	Formats       []string       `yaml:"formats"`
	DisabledRules []DisabledRule `yaml:"disabled_rules"`

	// Anciennes clés de la v1.0.0 (company et logo à la racine) : lues
	// puis reportées dans Issuer, jamais réécrites.
	LegacyCompany string `yaml:"company,omitempty"`
	LegacyLogo    string `yaml:"logo,omitempty"`
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
	logo := c.Issuer.Logo
	if logo == "" || filepath.IsAbs(logo) {
		return logo
	}
	return filepath.Join(dataDir, logo)
}

// Normalize reporte les anciennes clés dans Issuer et écarte une couleur invalide.
func (c *Config) Normalize() {
	if c.Issuer.Company == "" {
		c.Issuer.Company = c.LegacyCompany
	}
	if c.Issuer.Logo == "" {
		c.Issuer.Logo = c.LegacyLogo
	}
	c.LegacyCompany, c.LegacyLogo = "", ""
	c.Technician = strings.TrimSpace(c.Technician)
	if col := strings.TrimSpace(c.Issuer.Color); col != "" && !ValidColor(col) {
		c.Issuer.Color = ""
	} else {
		c.Issuer.Color = col
	}
}

// ValidColor accepte une couleur CSS #rrggbb.
func ValidColor(s string) bool {
	if len(s) != 7 || s[0] != '#' {
		return false
	}
	for _, r := range s[1:] {
		if !strings.ContainsRune("0123456789abcdefABCDEF", r) {
			return false
		}
	}
	return true
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
	c.Normalize()
	return c, nil
}

// Template est le fichier d'exemple créé au premier lancement.
const Template = `# Configuration d'Aplomb / Aplomb configuration
# Toutes les clés sont facultatives. / All keys are optional.

# Technicien affiché sur la page de garde du rapport.
technician: ""

# Langue de l'outil et du rapport : fr | en
lang: ""
report_lang: ""

# Émetteur du rapport (page de garde et pied de page), comme dans Arpent et Jalon.
issuer:
  name: ""
  company: ""
  contact: ""     # adresse, téléphone, courriel
  legal: ""       # mentions légales en pied de rapport
  color: ""       # couleur principale, ex. "#1f5f8b"
  logo: ""        # PNG, JPEG ou SVG, relatif à ce dossier : logo.png

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
