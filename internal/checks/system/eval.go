package system

import (
	"strconv"
	"strings"

	"github.com/maxb1906/aplomb/internal/model"
	"github.com/maxb1906/aplomb/internal/rules"
)

func init() {
	rules.Register("SYS-001", uac)
	rules.Register("SYS-002", alwaysInstallElevated)
	rules.Register("SYS-003", rdpNLA)
	rules.Register("SYS-004", llmnr)
	rules.Register("SYS-005", netbios)
	rules.Register("SYS-006", wdigest)
	rules.Register("SYS-007", lsaProtection)
	rules.Register("SYS-008", credentialGuard)
	rules.Register("SYS-009", psv2)
	rules.Register("SYS-010", scriptBlockLogging)
	rules.Register("SYS-011", autorun)
}

func sys(c *rules.Ctx) (*model.System, *rules.Outcome) {
	s := c.Snap.System
	if s == nil {
		o := rules.Missing(c.Snap.Gaps.Get("system"))
		return nil, &o
	}
	return s, nil
}

func show(v model.RegValue) string {
	if !v.Exists {
		return "(absent)"
	}
	if v.Num != nil {
		return strconv.FormatUint(*v.Num, 10)
	}
	return v.Str
}

func evOf(s *model.System, ids ...string) map[string]string {
	ev := map[string]string{}
	for _, id := range ids {
		v := s.Value(id)
		k := v.Path + `\` + v.Name
		if v.Path == "" {
			k = id
		}
		ev[k] = show(v)
	}
	return ev
}

// regCheck : le contrôle échoue si bad(valeur) ; le constat est marqué GPO si
// la valeur fautive vient d'une stratégie.
func regCheck(c *rules.Ctx, id string, bad func(v model.RegValue) bool, extra ...string) rules.Outcome {
	s, o := sys(c)
	if o != nil {
		return *o
	}
	v := s.Value(id)
	ev := evOf(s, append([]string{id}, extra...)...)
	if !bad(v) {
		return rules.Passed(ev)
	}
	return rules.Failed(rules.Finding{Evidence: ev, GPO: v.Policy})
}

func uac(c *rules.Ctx) rules.Outcome {
	s, o := sys(c)
	if o != nil {
		return *o
	}
	lua, consent := s.Value("uac_lua"), s.Value("uac_consent_admin")
	ev := evOf(s, "uac_lua", "uac_consent_admin")
	off := lua.Exists && lua.Uint(1) == 0
	silent := consent.Exists && consent.Uint(5) == 0
	if !off && !silent {
		return rules.Passed(ev)
	}
	return rules.Failed(rules.Finding{Evidence: ev})
}

func alwaysInstallElevated(c *rules.Ctx) rules.Outcome {
	s, o := sys(c)
	if o != nil {
		return *o
	}
	m, u := s.Value("aie_hklm").Uint(0) == 1, s.Value("aie_hkcu").Uint(0) == 1
	ev := evOf(s, "aie_hklm", "aie_hkcu")
	switch {
	case m && u:
		return rules.Failed(rules.Finding{Level: rules.Critical, Evidence: ev, GPO: true})
	case m:
		// Exploitable seulement si la valeur utilisateur est aussi à 1.
		return rules.Failed(rules.Finding{Level: rules.Warning, Evidence: ev, GPO: true})
	}
	return rules.Passed(ev)
}

func rdpNLA(c *rules.Ctx) rules.Outcome {
	s, o := sys(c)
	if o != nil {
		return *o
	}
	deny := s.Value("rdp_deny")
	if deny.Uint(1) == 1 {
		return rules.NA("rdp_off")
	}
	nla := s.Value("rdp_nla")
	ev := evOf(s, "rdp_deny", "rdp_nla")
	if nla.Uint(1) == 1 {
		return rules.Passed(ev)
	}
	return rules.Failed(rules.Finding{Evidence: ev, GPO: nla.Policy})
}

func llmnr(c *rules.Ctx) rules.Outcome {
	return regCheck(c, "llmnr", func(v model.RegValue) bool { return v.Uint(1) != 0 })
}

func netbios(c *rules.Ctx) rules.Outcome {
	s, o := sys(c)
	if o != nil {
		return *o
	}
	if s.NetBTDisabled {
		return rules.Passed(map[string]string{"netbt": "disabled"})
	}
	var on []string
	for _, i := range s.NetBIOS {
		if i.Options != 2 {
			on = append(on, i.ID+"="+strconv.Itoa(i.Options))
		}
	}
	if len(on) == 0 {
		return rules.Passed(map[string]string{"interfaces": strconv.Itoa(len(s.NetBIOS))})
	}
	return rules.Failed(rules.Finding{Evidence: map[string]string{"interfaces": strings.Join(on, ", ")}})
}

func wdigest(c *rules.Ctx) rules.Outcome {
	return regCheck(c, "wdigest", func(v model.RegValue) bool { return v.Uint(0) == 1 })
}

func lsaProtection(c *rules.Ctx) rules.Outcome {
	s, o := sys(c)
	if o != nil {
		return *o
	}
	ev := evOf(s, "runasppl", "runasppl_boot")
	if s.LSAProtected != nil {
		ev["lsass_protected"] = strconv.FormatBool(*s.LSAProtected)
		if *s.LSAProtected {
			return rules.Passed(ev)
		}
		return rules.Failed(rules.Finding{Evidence: ev})
	}
	ppl, boot := s.Value("runasppl").Uint(0), s.Value("runasppl_boot").Uint(0)
	if ppl == 1 || ppl == 2 || boot == 1 || boot == 2 {
		return rules.Passed(ev)
	}
	// Sans admin, l'état réel de lsass n'est pas lisible : l'absence de valeur
	// ne prouve rien (Windows 11 l'active parfois par défaut).
	if !c.Snap.Host.Elevated {
		return rules.Unchecked(model.Gap{Reason: model.GapAdmin, Detail: "lsass protection level"})
	}
	return rules.Failed(rules.Finding{Evidence: ev})
}

func credentialGuard(c *rules.Ctx) rules.Outcome {
	s, o := sys(c)
	if o != nil {
		return *o
	}
	if s.CredentialGuard == nil {
		return rules.Missing(s.Gaps.Get("credential_guard"))
	}
	ev := map[string]string{"credential_guard_running": strconv.FormatBool(*s.CredentialGuard)}
	if *s.CredentialGuard {
		return rules.Passed(ev)
	}
	return rules.Failed(rules.Finding{Evidence: ev, GPO: s.Value("lsacfgflags").Policy})
}

func psv2(c *rules.Ctx) rules.Outcome {
	s, o := sys(c)
	if o != nil {
		return *o
	}
	if s.PSv2 == nil {
		return rules.Missing(s.Gaps.Get("psv2"))
	}
	ev := map[string]string{"psv2_installed": strconv.FormatBool(*s.PSv2)}
	if !*s.PSv2 {
		return rules.Passed(ev)
	}
	return rules.Failed(rules.Finding{Evidence: ev, Params: map[string]string{"role": c.Role}})
}

func scriptBlockLogging(c *rules.Ctx) rules.Outcome {
	return regCheck(c, "sbl", func(v model.RegValue) bool { return v.Uint(0) != 1 })
}

func autorun(c *rules.Ctx) rules.Outcome {
	s, o := sys(c)
	if o != nil {
		return *o
	}
	ev := evOf(s, "nodrivetypeautorun", "noautorun")
	nd := s.Value("nodrivetypeautorun")
	if s.Value("noautorun").Uint(0) == 1 || (nd.Exists && (nd.Uint(0)&0xFF == 0xFF || nd.Uint(0)&0x04 != 0)) {
		return rules.Passed(ev)
	}
	return rules.Failed(rules.Finding{Evidence: ev})
}
