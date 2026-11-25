package accounts

import (
	"strconv"
	"strings"

	"github.com/maxb1906/aplomb/internal/model"
	"github.com/maxb1906/aplomb/internal/rules"
)

// Longueurs minimales attendues ; 14 caractères compensent l'absence d'expiration.
const (
	minLenWorkstation = 12
	minLenServer      = 14
	compensatingLen   = 14
	maxExtraAdmins    = 3
)

func init() {
	rules.Register("ACC-001", minLength)
	rules.Register("ACC-002", lockout)
	rules.Register("ACC-003", maxAge)
	rules.Register("ACC-004", evalComplexity)
	rules.Register("ACC-005", guest)
	rules.Register("ACC-006", builtinAdmin)
	rules.Register("ACC-007", adminCount)
	rules.Register("ACC-008", passwordNotRequired)
	rules.Register("ACC-009", neverExpires)
	rules.Register("ACC-010", evalLAPS)
}

func section(c *rules.Ctx) (*model.Accounts, *rules.Outcome) {
	a := c.Snap.Accounts
	if a == nil {
		o := rules.Missing(c.Snap.Gaps.Get("accounts"))
		return nil, &o
	}
	return a, nil
}

func pol(c *rules.Ctx) (*model.PasswordPolicy, *rules.Outcome) {
	a, o := section(c)
	if o != nil {
		return nil, o
	}
	if a.Policy == nil {
		o := rules.Missing(a.Gaps.Get("policy"))
		return nil, &o
	}
	return a.Policy, nil
}

// fromGPO : sur une machine du domaine, la politique de mots de passe vient de
// la GPO du domaine (« Default Domain Policy »).
func fromGPO(c *rules.Ctx) bool { return c.Snap.Host.JoinType == "domain" }

func wantLen(c *rules.Ctx) int {
	if c.Role == model.RoleWorkstation {
		return minLenWorkstation
	}
	return minLenServer
}

func policyEv(p *model.PasswordPolicy) map[string]string {
	ev := map[string]string{
		"min_length": strconv.Itoa(p.MinLength), "max_age_days": strconv.Itoa(p.MaxAgeDays), "history": strconv.Itoa(p.History),
		"lockout_threshold": strconv.Itoa(p.LockoutThreshold), "lockout_duration_min": strconv.Itoa(p.LockoutDurationMin),
	}
	if p.Complexity != nil {
		ev["complexity"] = strconv.FormatBool(*p.Complexity)
	}
	return ev
}

func minLength(c *rules.Ctx) rules.Outcome {
	p, o := pol(c)
	if o != nil {
		return *o
	}
	want := wantLen(c)
	if p.MinLength >= want {
		return rules.Passed(policyEv(p))
	}
	return rules.Failed(rules.Finding{Evidence: policyEv(p), GPO: fromGPO(c),
		Params: map[string]string{"current": strconv.Itoa(p.MinLength), "want": strconv.Itoa(want)}})
}

func lockout(c *rules.Ctx) rules.Outcome {
	p, o := pol(c)
	if o != nil {
		return *o
	}
	if p.LockoutThreshold > 0 {
		return rules.Passed(policyEv(p))
	}
	return rules.Failed(rules.Finding{Evidence: policyEv(p), GPO: fromGPO(c)})
}

func maxAge(c *rules.Ctx) rules.Outcome {
	p, o := pol(c)
	if o != nil {
		return *o
	}
	if p.MaxAgeDays >= 0 || p.MinLength >= compensatingLen {
		return rules.Passed(policyEv(p))
	}
	return rules.Failed(rules.Finding{Evidence: policyEv(p), GPO: fromGPO(c),
		Params: map[string]string{"want": strconv.Itoa(compensatingLen)}})
}

func evalComplexity(c *rules.Ctx) rules.Outcome {
	p, o := pol(c)
	if o != nil {
		return *o
	}
	if p.Complexity == nil {
		return rules.Missing(c.Snap.Accounts.Gaps.Get("complexity"))
	}
	if *p.Complexity || p.MinLength >= compensatingLen {
		return rules.Passed(policyEv(p))
	}
	return rules.Failed(rules.Finding{Evidence: policyEv(p), GPO: fromGPO(c)})
}

func usersOf(c *rules.Ctx) ([]model.LocalUser, *rules.Outcome) {
	a, o := section(c)
	if o != nil {
		return nil, o
	}
	if a.Users == nil {
		o := rules.Missing(a.Gaps.Get("users"))
		return nil, &o
	}
	return a.Users, nil
}

func byRID(c *rules.Ctx, rid uint32) rules.Outcome {
	us, o := usersOf(c)
	if o != nil {
		return *o
	}
	for _, u := range us {
		if u.RID == rid {
			ev := map[string]string{"account": u.Name, "enabled": strconv.FormatBool(u.Enabled)}
			if !u.Enabled {
				return rules.Passed(ev)
			}
			return rules.Failed(rules.Finding{Object: u.Name, Evidence: ev, Params: map[string]string{"user": u.Name, "role": c.Role}})
		}
	}
	return rules.Passed(map[string]string{"rid": strconv.Itoa(int(rid)), "account": "absent"})
}

func guest(c *rules.Ctx) rules.Outcome        { return byRID(c, 501) }
func builtinAdmin(c *rules.Ctx) rules.Outcome { return byRID(c, 500) }

// builtinAdminMember : comptes attendus dans Administrateurs.
func builtinAdminMember(m model.GroupMember) bool {
	return strings.HasSuffix(m.SID, "-500") || strings.HasSuffix(m.SID, "-512") || strings.HasSuffix(m.SID, "-519") ||
		(strings.HasPrefix(m.SID, "S-1-12-1-") && m.Kind != "user") // rôles Entra ID (administrateurs du tenant / des appareils)
}

func adminCount(c *rules.Ctx) rules.Outcome {
	a, o := section(c)
	if o != nil {
		return *o
	}
	if a.Admins == nil {
		return rules.Missing(a.Gaps.Get("admins"))
	}
	var names, extra []string
	var extraMembers []model.GroupMember
	for _, m := range a.Admins {
		names = append(names, m.Name)
		if !builtinAdminMember(m) {
			extra = append(extra, m.Name)
			extraMembers = append(extraMembers, m)
		}
	}
	ev := map[string]string{"members": strings.Join(names, ", "), "count": strconv.Itoa(len(a.Admins))}
	if len(extra) <= maxExtraAdmins {
		return rules.Passed(ev)
	}
	var fs []rules.Finding
	for _, m := range extraMembers {
		fs = append(fs, rules.Finding{Object: m.Name, Evidence: map[string]string{"sid": m.SID, "kind": m.Kind},
			Params: map[string]string{"member": m.Name, "count": strconv.Itoa(len(extra)), "max": strconv.Itoa(maxExtraAdmins)}})
	}
	return rules.Failed(fs...)
}

func passwordNotRequired(c *rules.Ctx) rules.Outcome {
	us, o := usersOf(c)
	if o != nil {
		return *o
	}
	var fs []rules.Finding
	for _, u := range us {
		if u.Enabled && u.PasswordNotRequired {
			fs = append(fs, rules.Finding{Object: u.Name, Params: map[string]string{"user": u.Name}})
		}
	}
	if len(fs) == 0 {
		return rules.Passed(nil)
	}
	return rules.Failed(fs...)
}

func neverExpires(c *rules.Ctx) rules.Outcome {
	us, o := usersOf(c)
	if o != nil {
		return *o
	}
	p := c.Snap.Accounts.Policy
	// Sans durée maximale dans la politique, l'option n'a pas d'effet (voir ACC-003) ;
	// une longueur de 14 caractères compense l'absence d'expiration.
	if p != nil && (p.MaxAgeDays < 0 || p.MinLength >= compensatingLen) {
		return rules.Passed(map[string]string{"policy": "compensated"})
	}
	var fs []rules.Finding
	for _, u := range us {
		if u.Enabled && u.PasswordNeverExpires {
			fs = append(fs, rules.Finding{Object: u.Name, Params: map[string]string{"user": u.Name}})
		}
	}
	if len(fs) == 0 {
		return rules.Passed(nil)
	}
	return rules.Failed(fs...)
}

func evalLAPS(c *rules.Ctx) rules.Outcome {
	h := c.Snap.Host
	if !h.Joined() {
		return rules.NA("not_joined")
	}
	a, o := section(c)
	if o != nil {
		return *o
	}
	l := a.LAPS
	if l == nil {
		return rules.Missing(a.Gaps.Get("laps"))
	}
	ev := map[string]string{"windows_laps": strconv.FormatBool(l.WindowsConfigured), "backup_directory": strconv.Itoa(l.BackupDirectory), "legacy_laps": strconv.FormatBool(l.Legacy)}
	if (l.WindowsConfigured && l.BackupDirectory > 0) || l.Legacy {
		return rules.Passed(ev)
	}
	ou := ""
	if i := strings.Index(h.ComputerDN, ","); i > 0 && h.JoinType == "domain" {
		ou = h.ComputerDN[i+1:]
	}
	return rules.Failed(rules.Finding{Evidence: ev, Params: map[string]string{"ou": ou, "join": h.JoinType}})
}
