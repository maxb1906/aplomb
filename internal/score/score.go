// Package score calcule le score de conformité (§ 5.5).
package score

import (
	"math"

	"github.com/maxb1906/aplomb/internal/rules"
)

// CapScore est le score maximal quand un contrôle Critique est en défaut :
// la note est plafonnée à C (évite un 92/100 avec Defender désactivé).
const CapScore = 74

// Counts compte les contrôles par statut.
type Counts struct {
	Pass          int `json:"pass"`
	Fail          int `json:"fail"`
	NotChecked    int `json:"not_checked"`
	NotApplicable int `json:"not_applicable"`
	Accepted      int `json:"accepted_risk"`
	Critical      int `json:"critical"` // contrôles en défaut de niveau Critique
	Warning       int `json:"warning"`
	Info          int `json:"info"`
}

// Category est le score d'une catégorie (-1 : rien n'a pu être vérifié).
type Category struct {
	Category string `json:"category"`
	Score    int    `json:"score"`
	Grade    string `json:"grade"`
	Counts   Counts `json:"counts"`
}

// Score est le résultat global.
type Score struct {
	Score      int        `json:"score"`     // après plafond
	RawScore   int        `json:"raw_score"` // avant plafond
	Grade      string     `json:"grade"`
	Capped     bool       `json:"capped"`
	Coverage   int        `json:"coverage"` // % des contrôles applicables effectivement vérifiés
	Counts     Counts     `json:"counts"`
	Categories []Category `json:"categories"`
}

// Grade traduit un score en note A → E (« - » si non calculable).
func Grade(score int) string {
	switch {
	case score < 0:
		return "-"
	case score >= 90:
		return "A"
	case score >= 75:
		return "B"
	case score >= 60:
		return "C"
	case score >= 40:
		return "D"
	default:
		return "E"
	}
}

type acc struct {
	ok, total int
	c         Counts
}

func (a *acc) add(r rules.Result, ruleLevel string) {
	switch r.Status {
	case rules.Pass:
		a.c.Pass++
		w := rules.Weight(ruleLevel)
		a.ok += w
		a.total += w
	case rules.Fail:
		a.c.Fail++
		a.total += rules.Weight(r.Level)
		switch r.Level {
		case rules.Critical:
			a.c.Critical++
		case rules.Warning:
			a.c.Warning++
		default:
			a.c.Info++
		}
	case rules.NotChecked:
		a.c.NotChecked++
	case rules.NotApplicable:
		a.c.NotApplicable++
	case rules.AcceptedRisk:
		a.c.Accepted++
	}
}

func (a *acc) score() int {
	if a.total == 0 {
		return -1
	}
	return int(math.Round(100 * float64(a.ok) / float64(a.total)))
}

// Compute calcule le score global et par catégorie. Les contrôles non
// vérifiés, non applicables et acceptés sont exclus du calcul.
func Compute(results []rules.Result, cat *rules.Catalog) Score {
	global := &acc{}
	per := map[string]*acc{}
	for _, r := range results {
		lvl := r.Level
		if rule := cat.Get(r.RuleID); rule != nil {
			lvl = rule.Level
		}
		global.add(r, lvl)
		if per[r.Category] == nil {
			per[r.Category] = &acc{}
		}
		per[r.Category].add(r, lvl)
	}
	s := Score{RawScore: global.score(), Counts: global.c}
	s.Score = s.RawScore
	if global.c.Critical > 0 && s.Score > CapScore {
		s.Score, s.Capped = CapScore, true
	}
	s.Grade = Grade(s.Score)
	checked := global.c.Pass + global.c.Fail + global.c.Accepted
	if all := checked + global.c.NotChecked; all > 0 {
		s.Coverage = int(math.Floor(100 * float64(checked) / float64(all)))
	}
	for _, c := range rules.Categories {
		a := per[c]
		if a == nil {
			continue
		}
		sc := a.score()
		s.Categories = append(s.Categories, Category{Category: c, Score: sc, Grade: Grade(sc), Counts: a.c})
	}
	return s
}
