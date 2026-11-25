// Package rules charge le catalogue des règles d'audit (assets/rules.yaml) et
// évalue un snapshot. Les métadonnées et les textes FR/EN d'une règle sont dans
// le YAML ; sa logique est une fonction Go (Evaluator) enregistrée sous le même
// identifiant par le package de contrôle concerné (internal/checks/...).
package rules

import (
	"fmt"
	"sort"
	"strings"
	"text/template"

	"gopkg.in/yaml.v3"
)

// Niveaux de gravité.
const (
	Info     = "info"
	Warning  = "warning"
	Critical = "critical"
)

// Weight renvoie le poids d'un niveau dans le score (§ 5.5).
func Weight(level string) int {
	switch level {
	case Critical:
		return 10
	case Warning:
		return 4
	default:
		return 1
	}
}

// Rank ordonne les niveaux (critique > attention > info).
func Rank(level string) int {
	switch level {
	case Critical:
		return 3
	case Warning:
		return 2
	case Info:
		return 1
	}
	return 0
}

// Categories dans l'ordre d'affichage du rapport.
var Categories = []string{"system", "services", "tasks", "accounts", "bitlocker", "defender", "smb", "firewall"}

// Text regroupe les textes d'une règle dans une langue. Les variables {nom}
// sont remplacées par les paramètres du constat.
type Text struct {
	Title   string `yaml:"title"`
	Summary string `yaml:"summary"` // explication simple, pour le client
	Detail  string `yaml:"detail"`  // détail technique
	Impact  string `yaml:"impact"`  // avertissement sur la remédiation
	GPO     string `yaml:"gpo"`     // emplacement du paramètre dans une GPO
}

// Ref est une référence indicative (Microsoft, ANSSI, MITRE ATT&CK).
type Ref struct {
	Name string `yaml:"name"`
	URL  string `yaml:"url"`
}

// Rule est une règle d'audit.
type Rule struct {
	ID          string          `yaml:"id"`
	Category    string          `yaml:"category"`
	Level       string          `yaml:"level"`
	Profiles    []string        `yaml:"profiles"`
	Admin       bool            `yaml:"admin"`
	Refs        []Ref           `yaml:"refs"`
	Remediation string          `yaml:"remediation"`
	Texts       map[string]Text `yaml:"text"`

	tmpl *template.Template
}

// Text renvoie les textes dans lang, avec repli sur le français champ par champ.
func (r *Rule) Text(lang string) Text {
	t, fr := r.Texts[lang], r.Texts["fr"]
	if t.Title == "" {
		t.Title = fr.Title
	}
	if t.Summary == "" {
		t.Summary = fr.Summary
	}
	if t.Detail == "" {
		t.Detail = fr.Detail
	}
	if t.Impact == "" {
		t.Impact = fr.Impact
	}
	if t.GPO == "" {
		t.GPO = fr.GPO
	}
	return t
}

// AppliesTo indique si la règle concerne une machine de ce rôle.
func (r *Rule) AppliesTo(role string) bool {
	if len(r.Profiles) == 0 {
		return true
	}
	for _, p := range r.Profiles {
		if p == role {
			return true
		}
	}
	return false
}

// RenderRemediation produit la commande PowerShell pour les paramètres donnés.
func (r *Rule) RenderRemediation(params map[string]string) (string, error) {
	if r.tmpl == nil {
		return "", nil
	}
	var b strings.Builder
	if err := r.tmpl.Execute(&b, params); err != nil {
		return "", err
	}
	return strings.TrimSpace(b.String()), nil
}

// Catalog est l'ensemble des règles, indexées par identifiant.
type Catalog struct {
	Rules []*Rule
	byID  map[string]*Rule
}

// Get renvoie la règle id (nil si inconnue).
func (c *Catalog) Get(id string) *Rule { return c.byID[id] }

// TemplateFuncs sont disponibles dans les modèles de remédiation.
var TemplateFuncs = template.FuncMap{
	// ps entoure une valeur de guillemets simples PowerShell, échappés.
	"ps": func(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" },
}

// Parse lit et valide un catalogue YAML.
func Parse(data []byte) (*Catalog, error) {
	var list []*Rule
	if err := yaml.Unmarshal(data, &list); err != nil {
		return nil, fmt.Errorf("rules.yaml : %w", err)
	}
	c := &Catalog{Rules: list, byID: map[string]*Rule{}}
	cats := map[string]bool{}
	for _, cat := range Categories {
		cats[cat] = true
	}
	for _, r := range list {
		if r.ID == "" {
			return nil, fmt.Errorf("rules.yaml : règle sans identifiant")
		}
		if c.byID[r.ID] != nil {
			return nil, fmt.Errorf("rules.yaml : identifiant en double %s", r.ID)
		}
		if !cats[r.Category] {
			return nil, fmt.Errorf("%s : catégorie inconnue %q", r.ID, r.Category)
		}
		if Rank(r.Level) == 0 {
			return nil, fmt.Errorf("%s : niveau inconnu %q", r.ID, r.Level)
		}
		for _, p := range r.Profiles {
			if p != "workstation" && p != "server" && p != "dc" {
				return nil, fmt.Errorf("%s : profil inconnu %q", r.ID, p)
			}
		}
		for _, lang := range []string{"fr", "en"} {
			t := r.Texts[lang]
			if strings.TrimSpace(t.Title) == "" || strings.TrimSpace(t.Summary) == "" {
				return nil, fmt.Errorf("%s : titre ou résumé %s manquant", r.ID, lang)
			}
		}
		if strings.TrimSpace(r.Remediation) != "" {
			t, err := template.New(r.ID).Funcs(TemplateFuncs).Option("missingkey=error").Parse(r.Remediation)
			if err != nil {
				return nil, fmt.Errorf("%s : remédiation : %w", r.ID, err)
			}
			r.tmpl = t
		}
		c.byID[r.ID] = r
	}
	sort.SliceStable(c.Rules, func(i, j int) bool { return c.Rules[i].ID < c.Rules[j].ID })
	return c, nil
}
