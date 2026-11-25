package rules

import (
	"fmt"
	"sort"
	"time"

	"github.com/maxb1906/aplomb/internal/model"
)

// Statuts d'un contrôle (§ 6).
type Status string

const (
	Pass          Status = "pass"
	Fail          Status = "fail"
	NotChecked    Status = "not_checked"
	NotApplicable Status = "not_applicable"
	AcceptedRisk  Status = "accepted_risk"
)

// Finding est un objet en défaut (service, tâche, partage…), ou la machine
// elle-même quand Object est vide.
type Finding struct {
	Object string `json:"object,omitempty"`
	// Level remplace le niveau de la règle pour ce constat (ex. Critique si le
	// dossier est réellement inscriptible).
	Level    string            `json:"level,omitempty"`
	Evidence map[string]string `json:"evidence,omitempty"`
	// Params alimentent les textes {nom} et le modèle de remédiation.
	Params map[string]string `json:"params,omitempty"`
	// GPO : le paramètre est imposé par une stratégie ; corriger dans la GPO.
	GPO         bool   `json:"gpo,omitempty"`
	Remediation string `json:"remediation,omitempty"`
}

// Outcome est ce que renvoie un Evaluator.
type Outcome struct {
	Status   Status
	Gap      model.Gap
	Note     string // clé i18n "note.<Note>" expliquant le statut
	NoteArgs []string
	Evidence map[string]string
	Findings []Finding
}

// Helpers pour écrire les évaluateurs.
func Passed(ev map[string]string) Outcome { return Outcome{Status: Pass, Evidence: ev} }
func Failed(f ...Finding) Outcome         { return Outcome{Status: Fail, Findings: f} }
func Unchecked(g model.Gap) Outcome       { return Outcome{Status: NotChecked, Gap: g} }
func NA(note string, args ...string) Outcome {
	return Outcome{Status: NotApplicable, Note: note, NoteArgs: args}
}

// Missing renvoie « non vérifié » ou « non applicable » selon la raison.
func Missing(g model.Gap) Outcome {
	if g.Reason == model.GapAbsent {
		return Outcome{Status: NotApplicable, Gap: g, Note: "absent"}
	}
	return Unchecked(g)
}

// Ctx est passé aux évaluateurs.
type Ctx struct {
	Snap *model.Snapshot
	Role string    // profil effectif
	Now  time.Time // date de référence (collecte)
}

// Evaluator applique une règle à un snapshot.
type Evaluator func(c *Ctx) Outcome

var evaluators = map[string]Evaluator{}

// Register associe la logique d'une règle à son identifiant (appelé dans init).
func Register(id string, fn Evaluator) {
	if _, dup := evaluators[id]; dup {
		panic("rules: évaluateur en double " + id)
	}
	evaluators[id] = fn
}

// Registered renvoie les identifiants dotés d'un évaluateur, triés.
func Registered() []string {
	ids := make([]string, 0, len(evaluators))
	for id := range evaluators {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

// Result est le résultat d'un contrôle dans le rapport.
type Result struct {
	RuleID       string            `json:"rule"`
	Category     string            `json:"category"`
	Status       Status            `json:"status"`
	Level        string            `json:"level"`
	Reason       string            `json:"reason,omitempty"`
	ReasonDetail string            `json:"reason_detail,omitempty"`
	Note         string            `json:"note,omitempty"`
	NoteArgs     []string          `json:"note_args,omitempty"`
	Evidence     map[string]string `json:"evidence,omitempty"`
	Findings     []Finding         `json:"findings,omitempty"`
	GPO          bool              `json:"gpo,omitempty"`
	Accepted     string            `json:"accepted_reason,omitempty"`
}

// Options d'évaluation.
type Options struct {
	Profile  string            // vide : rôle détecté de la machine
	Accepted map[string]string // règles désactivées (risque accepté) → justification
}

// Evaluate applique toutes les règles du catalogue au snapshot.
func (c *Catalog) Evaluate(s *model.Snapshot, opt Options) ([]Result, error) {
	role := opt.Profile
	if role == "" {
		role = s.Host.Role
	}
	if role == "" {
		role = model.RoleWorkstation
	}
	now := s.CollectedAt
	if now.IsZero() {
		now = time.Now()
	}
	ctx := &Ctx{Snap: s, Role: role, Now: now}
	var out []Result
	for _, r := range c.Rules {
		fn := evaluators[r.ID]
		if fn == nil {
			return nil, fmt.Errorf("rules: pas d'évaluateur pour %s", r.ID)
		}
		res := Result{RuleID: r.ID, Category: r.Category, Level: r.Level}
		var o Outcome
		if !r.AppliesTo(role) {
			o = NA("profile", role)
		} else {
			o = safeEval(fn, ctx)
		}
		res.Status, res.Note, res.NoteArgs, res.Evidence = o.Status, o.Note, o.NoteArgs, o.Evidence
		if o.Status == NotChecked || o.Gap.Reason != "" {
			res.Reason, res.ReasonDetail = o.Gap.Reason, o.Gap.Detail
		}
		if o.Status == Fail {
			if len(o.Findings) == 0 {
				o.Findings = []Finding{{}}
			}
			for i := range o.Findings {
				f := &o.Findings[i]
				if Rank(f.Level) > Rank(res.Level) {
					res.Level = f.Level
				}
				if f.GPO {
					res.GPO = true
				}
				cmd, err := r.RenderRemediation(f.Params)
				if err != nil {
					return nil, fmt.Errorf("%s : remédiation : %w", r.ID, err)
				}
				f.Remediation = cmd
			}
			// Le niveau le plus bas des constats peut être inférieur à celui de
			// la règle (ex. Attention au lieu de Critique) : on garde le max des
			// constats s'ils précisent tous un niveau.
			if allLevels(o.Findings) {
				res.Level = maxLevel(o.Findings)
			}
			res.Findings = o.Findings
			if why, ok := opt.Accepted[r.ID]; ok {
				res.Status, res.Accepted = AcceptedRisk, why
			}
		}
		out = append(out, res)
	}
	return out, nil
}

func allLevels(fs []Finding) bool {
	for _, f := range fs {
		if f.Level == "" {
			return false
		}
	}
	return len(fs) > 0
}

func maxLevel(fs []Finding) string {
	best := ""
	for _, f := range fs {
		if Rank(f.Level) > Rank(best) {
			best = f.Level
		}
	}
	return best
}

// safeEval protège l'audit d'un évaluateur qui planterait sur des données inattendues.
func safeEval(fn Evaluator, c *Ctx) (o Outcome) {
	defer func() {
		if r := recover(); r != nil {
			o = Unchecked(model.Gap{Reason: model.GapError, Detail: fmt.Sprint("evaluator panic: ", r)})
		}
	}()
	return fn(c)
}
