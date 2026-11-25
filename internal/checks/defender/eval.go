package defender

import (
	"strconv"
	"strings"

	"github.com/maxb1906/aplomb/internal/model"
	"github.com/maxb1906/aplomb/internal/rules"
)

const maxSignatureAge = 7

func init() {
	rules.Register("DEF-001", realTime)
	rules.Register("DEF-002", tamper)
	rules.Register("DEF-003", signatures)
	rules.Register("DEF-004", exclusions)
	rules.Register("DEF-005", cloud)
	rules.Register("DEF-006", pua)
	rules.Register("DEF-007", asr)
}

// status renvoie l'état de Defender, ou l'Outcome à rendre : non applicable si
// un autre antivirus est actif (Defender passe alors normalement en mode passif).
func status(c *rules.Ctx) (*model.Defender, *rules.Outcome) {
	d := c.Snap.Defender
	if d == nil {
		o := rules.Missing(c.Snap.Gaps.Get("defender"))
		return nil, &o
	}
	if len(d.OtherAV) > 0 && (d.Status == nil || !d.Status.RealTime) {
		o := rules.NA("other_av", strings.Join(d.OtherAV, ", "))
		return nil, &o
	}
	if d.Status != nil && strings.Contains(strings.ToLower(d.Status.RunningMode), "passive") {
		o := rules.NA("defender_passive", d.Status.RunningMode)
		return nil, &o
	}
	if d.Status == nil {
		o := rules.Missing(d.Gaps.Get("status"))
		return nil, &o
	}
	return d, nil
}

func statusEv(s *model.DefenderStatus) map[string]string {
	ev := map[string]string{"running_mode": s.RunningMode, "antivirus_enabled": strconv.FormatBool(s.AntivirusEnabled),
		"realtime": strconv.FormatBool(s.RealTime), "signature_age_days": strconv.Itoa(s.SignatureAgeDays)}
	if s.Tamper != nil {
		ev["tamper_protected"] = strconv.FormatBool(*s.Tamper)
	}
	return ev
}

func realTime(c *rules.Ctx) rules.Outcome {
	d, o := status(c)
	if o != nil {
		return *o
	}
	if d.Status.RealTime && d.Status.AntivirusEnabled {
		return rules.Passed(statusEv(d.Status))
	}
	return rules.Failed(rules.Finding{Evidence: statusEv(d.Status), GPO: d.PolicyRealTimeOff})
}

func tamper(c *rules.Ctx) rules.Outcome {
	d, o := status(c)
	if o != nil {
		return *o
	}
	if d.Status.Tamper == nil {
		return rules.Missing(model.Gap{Reason: model.GapAbsent, Detail: "IsTamperProtected"})
	}
	if *d.Status.Tamper {
		return rules.Passed(statusEv(d.Status))
	}
	return rules.Failed(rules.Finding{Evidence: statusEv(d.Status)})
}

func signatures(c *rules.Ctx) rules.Outcome {
	d, o := status(c)
	if o != nil {
		return *o
	}
	if d.Status.SignatureAgeDays <= maxSignatureAge {
		return rules.Passed(statusEv(d.Status))
	}
	return rules.Failed(rules.Finding{Evidence: statusEv(d.Status), Params: map[string]string{"days": strconv.Itoa(d.Status.SignatureAgeDays)}})
}

func exclusions(c *rules.Ctx) rules.Outcome {
	d, o := status(c)
	if o != nil {
		return *o
	}
	all := append([]model.Exclusion{}, d.PolicyExclusions...)
	visible := d.Prefs != nil && d.Prefs.ExclusionsVisible
	if d.Prefs != nil {
		all = append(all, d.Prefs.Exclusions...)
	}
	var fs []rules.Finding
	seen := map[string]bool{}
	for _, e := range all {
		k := e.Kind + "|" + strings.ToLower(e.Value)
		if seen[k] || !Broad(e.Kind, e.Value) {
			continue
		}
		seen[k] = true
		flag := map[string]string{"path": "-ExclusionPath", "extension": "-ExclusionExtension", "process": "-ExclusionProcess"}[e.Kind]
		fs = append(fs, rules.Finding{Object: e.Value + " (" + e.Kind + ")", GPO: e.Policy,
			Evidence: map[string]string{"kind": e.Kind, "value": e.Value, "policy": strconv.FormatBool(e.Policy)},
			Params:   map[string]string{"flag": flag, "value": e.Value}})
	}
	if len(fs) > 0 {
		return rules.Failed(fs...)
	}
	if !visible {
		return rules.Unchecked(model.Gap{Reason: model.GapAdmin, Detail: "MSFT_MpPreference exclusions hidden"})
	}
	return rules.Passed(map[string]string{"exclusions": strconv.Itoa(len(all))})
}

func prefs(c *rules.Ctx) (*model.DefenderPrefs, *rules.Outcome) {
	d, o := status(c)
	if o != nil {
		return nil, o
	}
	if d.Prefs == nil {
		o := rules.Missing(d.Gaps.Get("status"))
		return nil, &o
	}
	return d.Prefs, nil
}

func cloud(c *rules.Ctx) rules.Outcome {
	p, o := prefs(c)
	if o != nil {
		return *o
	}
	if p.MAPSReporting == nil {
		return rules.Missing(model.Gap{Reason: model.GapError, Detail: "MAPSReporting"})
	}
	ev := map[string]string{"maps_reporting": strconv.Itoa(*p.MAPSReporting)}
	samples := -1
	if p.SubmitSamples != nil {
		samples = *p.SubmitSamples
		ev["submit_samples"] = strconv.Itoa(samples)
	}
	if *p.MAPSReporting != 0 && samples != 2 {
		return rules.Passed(ev)
	}
	return rules.Failed(rules.Finding{Evidence: ev})
}

func pua(c *rules.Ctx) rules.Outcome {
	p, o := prefs(c)
	if o != nil {
		return *o
	}
	if p.PUA == nil {
		return rules.Missing(model.Gap{Reason: model.GapError, Detail: "PUAProtection"})
	}
	ev := map[string]string{"pua": strconv.Itoa(*p.PUA)}
	if *p.PUA != 0 {
		return rules.Passed(ev)
	}
	return rules.Failed(rules.Finding{Evidence: ev})
}

func asr(c *rules.Ctx) rules.Outcome {
	p, o := prefs(c)
	if o != nil {
		return *o
	}
	n := 0
	for _, r := range p.ASR {
		if r.Action == 1 || r.Action == 2 || r.Action == 6 {
			n++
		}
	}
	ev := map[string]string{"asr_rules_enabled": strconv.Itoa(n)}
	if n > 0 {
		return rules.Passed(ev)
	}
	return rules.Failed(rules.Finding{Evidence: ev})
}
