package defender

import (
	"strings"
	"time"

	"github.com/maxb1906/aplomb/internal/model"
	"github.com/maxb1906/aplomb/internal/win"
)

const (
	nsDefender = `root\Microsoft\Windows\Defender`
	policyKey  = `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender`
)

// Collect lit l'état et les préférences de Defender, les exclusions imposées
// par stratégie (lisibles sans admin) et les antivirus tiers.
func Collect(h model.Host) *model.Defender {
	out := &model.Defender{}
	out.PolicyRealTimeOff = win.ReadValue(policyKey+`\Real-Time Protection`, "DisableRealtimeMonitoring").Uint(0) == 1
	for kind, sub := range map[string]string{"path": "Paths", "extension": "Extensions", "process": "Processes"} {
		for _, v := range valueNames(policyKey + `\Exclusions\` + sub) {
			out.PolicyExclusions = append(out.PolicyExclusions, model.Exclusion{Kind: kind, Value: v, Policy: true})
		}
	}
	err := win.WithCOM(func() error {
		if err := win.WbemQuery(nsDefender, "SELECT * FROM MSFT_MpComputerStatus", func(o *win.Disp) error {
			st := &model.DefenderStatus{RunningMode: o.Str("AMRunningMode")}
			st.AMServiceEnabled, _ = o.Bool("AMServiceEnabled")
			st.AntivirusEnabled, _ = o.Bool("AntivirusEnabled")
			st.RealTime, _ = o.Bool("RealTimeProtectionEnabled")
			if tp, ok := o.Bool("IsTamperProtected"); ok {
				st.Tamper = &tp
			}
			if age, ok := o.Int("AntivirusSignatureAge"); ok {
				st.SignatureAgeDays = int(age)
			}
			if t, ok := cimDate(o.Str("AntivirusSignatureLastUpdated")); ok {
				st.SignatureUpdated = &t
			}
			out.Status = st
			return nil
		}); err != nil {
			return err
		}
		return win.WbemQuery(nsDefender, "SELECT * FROM MSFT_MpPreference", func(o *win.Disp) error {
			p := &model.DefenderPrefs{ExclusionsVisible: true}
			for kind, prop := range map[string]string{"path": "ExclusionPath", "extension": "ExclusionExtension", "process": "ExclusionProcess"} {
				vals, _ := o.Strings(prop)
				for _, v := range vals {
					if HiddenByDefender(v) {
						p.ExclusionsVisible = false
						continue
					}
					p.Exclusions = append(p.Exclusions, model.Exclusion{Kind: kind, Value: v})
				}
			}
			if n, ok := o.Int("MAPSReporting"); ok {
				p.MAPSReporting = model.Int(int(n))
			}
			if n, ok := o.Int("SubmitSamplesConsent"); ok {
				p.SubmitSamples = model.Int(int(n))
			}
			if n, ok := o.Int("PUAProtection"); ok {
				p.PUA = model.Int(int(n))
			}
			ids, _ := o.Strings("AttackSurfaceReductionRules_Ids")
			acts, _ := o.Ints("AttackSurfaceReductionRules_Actions")
			for i, id := range ids {
				a := 0
				if i < len(acts) {
					a = int(acts[i])
				}
				p.ASR = append(p.ASR, model.ASRRule{ID: id, Action: a})
			}
			out.Prefs = p
			return nil
		})
	})
	if err != nil {
		reason := model.GapError
		if win.IsNotFound(err) {
			reason = model.GapAbsent
		} else if win.IsAccessDenied(err) {
			reason = model.GapAdmin
		}
		out.Gaps.Set("status", reason, err.Error())
	}
	if h.Role == model.RoleWorkstation {
		out.OtherAV = otherAV()
	}
	return out
}

func valueNames(key string) []string {
	k, err := win.OpenKey(key)
	if err != nil {
		return nil
	}
	defer k.Close()
	names, _ := k.ReadValueNames(-1)
	return names
}

// otherAV lit les antivirus déclarés au Centre de sécurité Windows (postes de travail).
func otherAV() []string {
	out := []string{}
	_ = win.WithCOM(func() error {
		return win.WbemQuery(`root\SecurityCenter2`, "SELECT displayName, productState FROM AntiVirusProduct", func(o *win.Disp) error {
			name := o.Str("displayName")
			state, _ := o.Int("productState")
			low := strings.ToLower(name)
			if strings.Contains(low, "defender") || strings.Contains(low, "windows security") {
				return nil
			}
			if ActiveAV(state) {
				out = append(out, name)
			}
			return nil
		})
	})
	return out
}

// cimDate lit une date CIM (« 20261120093000.000000+060 »).
func cimDate(s string) (time.Time, bool) {
	if len(s) < 14 {
		return time.Time{}, false
	}
	t, err := time.ParseInLocation("20060102150405", s[:14], time.Local)
	return t, err == nil
}
