package report

import (
	"encoding/base64"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/maxb1906/aplomb/internal/i18n"
	"github.com/maxb1906/aplomb/internal/rules"
)

// Options de rendu.
type Options struct {
	Translator *i18n.Translator // langue du rapport
	Catalog    *rules.Catalog
	LogoPath   string // facultatif
}

type kv struct{ K, V string }

type findingView struct {
	Object      string
	Level       string
	Evidence    []kv
	Remediation string
	GPO         bool
}

type itemView struct {
	ID, Category, CategoryLabel string
	Status, StatusLabel         string
	Level, LevelLabel           string
	Title, Summary, Detail      string
	Impact, GPOPath             string
	Note, Reason                string
	Accepted                    string
	GPO, Admin                  bool
	Evidence                    []kv
	Findings                    []findingView
	Refs                        []rules.Ref
}

type categoryView struct {
	ID, Label    string
	Score        int
	Grade        string
	Pass, Failed int
	Items        []itemView
}

type view struct {
	R          *Report
	Lang       string
	Logo       string
	HostRows   []kv
	Summary    []string
	Issues     []itemView
	Accepted   []itemView
	NotChecked []itemView
	Categories []categoryView
	ScoreDash  string
	HasScore   bool
}

// replaceParams remplace les variables {nom} d'un texte de règle.
func replaceParams(s string, params map[string]string) string {
	if len(params) == 0 || !strings.Contains(s, "{") {
		return s
	}
	pairs := make([]string, 0, 2*len(params))
	for k, v := range params {
		pairs = append(pairs, "{"+k+"}", v)
	}
	return strings.NewReplacer(pairs...).Replace(s)
}

func sortedKV(m map[string]string) []kv {
	out := make([]kv, 0, len(m))
	for k, v := range m {
		out = append(out, kv{k, v})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].K < out[j].K })
	return out
}

func buildView(r *Report, o Options) *view {
	tr := o.Translator
	lang := tr.Lang()
	v := &view{R: r, Lang: lang, HasScore: r.Score.Score >= 0}
	if v.HasScore {
		// Circonférence du cercle de la jauge (r = 52) : 2πr ≈ 326,7.
		v.ScoreDash = strconv.FormatFloat(326.7*float64(r.Score.Score)/100, 'f', 1, 64)
	}
	v.Logo = logoURI(o.LogoPath)
	v.HostRows = hostRows(r, tr)
	v.Summary = summary(r, tr)

	cats := map[string]*categoryView{}
	for _, c := range r.Score.Categories {
		cats[c.Category] = &categoryView{ID: c.Category, Label: tr.T("category." + c.Category), Score: c.Score, Grade: c.Grade, Pass: c.Counts.Pass, Failed: c.Counts.Fail}
	}
	for _, res := range r.Checks {
		it := item(res, o)
		switch res.Status {
		case rules.Fail:
			v.Issues = append(v.Issues, it)
		case rules.AcceptedRisk:
			v.Accepted = append(v.Accepted, it)
		case rules.NotChecked:
			v.NotChecked = append(v.NotChecked, it)
		}
		if c := cats[res.Category]; c != nil {
			c.Items = append(c.Items, it)
		}
	}
	sort.SliceStable(v.Issues, func(i, j int) bool {
		a, b := rules.Rank(v.Issues[i].Level), rules.Rank(v.Issues[j].Level)
		if a != b {
			return a > b
		}
		return v.Issues[i].ID < v.Issues[j].ID
	})
	for _, c := range rules.Categories {
		if cv := cats[c]; cv != nil {
			v.Categories = append(v.Categories, *cv)
		}
	}
	return v
}

func item(res rules.Result, o Options) itemView {
	tr := o.Translator
	it := itemView{
		ID: res.RuleID, Category: res.Category, CategoryLabel: tr.T("category." + res.Category),
		Status: string(res.Status), StatusLabel: tr.T("status." + string(res.Status)),
		Level: res.Level, LevelLabel: tr.T("level." + res.Level),
		GPO: res.GPO, Accepted: res.Accepted, Evidence: sortedKV(res.Evidence),
	}
	var params map[string]string
	if len(res.Findings) > 0 {
		params = res.Findings[0].Params
	}
	if rule := o.Catalog.Get(res.RuleID); rule != nil {
		t := rule.Text(tr.Lang())
		it.Title = replaceParams(t.Title, params)
		it.Summary = replaceParams(t.Summary, params)
		it.Detail = replaceParams(t.Detail, params)
		it.Impact, it.GPOPath, it.Refs, it.Admin = t.Impact, t.GPO, rule.Refs, rule.Admin
	} else {
		it.Title = res.RuleID
	}
	if res.Note != "" {
		pairs := make([]string, 0, 2*len(res.NoteArgs))
		for i, a := range res.NoteArgs {
			if i == 0 && res.Note == "profile" {
				a = tr.T("role." + a)
			}
			pairs = append(pairs, "a"+strconv.Itoa(i), a)
		}
		it.Note = tr.T("note."+res.Note, pairs...)
	}
	if res.Reason != "" {
		it.Reason = tr.T("reason." + res.Reason)
	}
	for _, f := range res.Findings {
		lvl := f.Level
		if lvl == "" {
			lvl = res.Level
		}
		it.Findings = append(it.Findings, findingView{Object: f.Object, Level: lvl, Evidence: sortedKV(f.Evidence), Remediation: f.Remediation, GPO: f.GPO})
	}
	return it
}

func hostRows(r *Report, tr *i18n.Translator) []kv {
	h := r.Host
	yes := func(b bool) string {
		if b {
			return tr.T("common.yes")
		}
		return tr.T("common.no")
	}
	tri := func(b *bool) string {
		if b == nil {
			return tr.T("common.unknown")
		}
		return yes(*b)
	}
	osv := strings.TrimSpace(h.OS + " " + h.DisplayVersion)
	if h.Build != "" {
		osv += " (build " + h.Build
		if h.UBR > 0 {
			osv += "." + strconv.FormatUint(h.UBR, 10)
		}
		osv += ")"
	}
	join := tr.T("join."+h.JoinType, "domain", h.Domain)
	if h.EntraJoined {
		join += " · " + tr.T("join.entra", "tenant", h.EntraTenant)
	}
	last := tr.T("common.unknown")
	if h.LastUpdate != nil {
		last = formatDate(*h.LastUpdate, tr.Lang())
		if h.LastUpdateKB != "" {
			last += " (" + h.LastUpdateKB + ")"
		}
	}
	tpm := tri(h.TPMPresent)
	if h.TPMVersion != "" {
		tpm += " (" + h.TPMVersion + ")"
	}
	rows := []kv{
		{tr.T("host.name"), h.Name},
		{tr.T("host.os"), osv},
		{tr.T("host.role"), tr.T("role." + h.Role)},
		{tr.T("host.join"), join},
		{tr.T("host.user"), h.User},
		{tr.T("host.elevated"), yes(h.Elevated)},
		{tr.T("host.firmware"), strings.ToUpper(h.Firmware)},
		{tr.T("host.secure_boot"), tri(h.SecureBoot)},
		{tr.T("host.tpm"), tpm},
		{tr.T("host.portable"), tri(h.Portable)},
		{tr.T("host.last_update"), last},
	}
	if r.Meta.Profile != "" && r.Meta.Profile != h.Role {
		rows = append(rows, kv{tr.T("host.profile"), tr.T("role." + r.Meta.Profile)})
	}
	return rows
}

// summary rédige le résumé non technique.
func summary(r *Report, tr *i18n.Translator) []string {
	s := r.Score
	var out []string
	if s.Score >= 0 {
		out = append(out, tr.T("summary.grade."+s.Grade, "score", strconv.Itoa(s.Score)))
	}
	c := s.Counts
	if c.Fail == 0 {
		out = append(out, tr.T("summary.no_issue"))
	} else {
		out = append(out, tr.T("summary.issues", "critical", strconv.Itoa(c.Critical), "warning", strconv.Itoa(c.Warning), "info", strconv.Itoa(c.Info)))
	}
	if s.Capped {
		out = append(out, tr.T("summary.capped", "raw", strconv.Itoa(s.RawScore)))
	}
	if c.NotChecked > 0 {
		key := "summary.coverage"
		if !r.Meta.Elevated {
			key = "summary.coverage_admin"
		}
		out = append(out, tr.T(key, "coverage", strconv.Itoa(s.Coverage)))
	}
	if c.Accepted > 0 {
		out = append(out, tr.T("summary.accepted", "n", strconv.Itoa(c.Accepted)))
	}
	return out
}

func logoURI(path string) string {
	if path == "" {
		return ""
	}
	data, err := os.ReadFile(path)
	if err != nil || len(data) > 2<<20 {
		return ""
	}
	mime := http.DetectContentType(data)
	if strings.HasSuffix(strings.ToLower(path), ".svg") {
		mime = "image/svg+xml"
	}
	if !strings.HasPrefix(mime, "image/") {
		return ""
	}
	return "data:" + mime + ";base64," + base64.StdEncoding.EncodeToString(data)
}
