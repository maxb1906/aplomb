package firewall

import (
	"strings"

	"github.com/maxb1906/aplomb/internal/checks/services"
	"github.com/maxb1906/aplomb/internal/model"
	"github.com/maxb1906/aplomb/internal/win"
)

const (
	dirIn       = 1
	actionAllow = 1
	policyBase  = `HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\`
)

var profileDefs = []struct {
	bit  int
	name string
	key  string
}{{1, "Domain", "DomainProfile"}, {2, "Private", "PrivateProfile"}, {4, "Public", "PublicProfile"}}

// Collect lit les profils et les règles via HNetCfg.FwPolicy2 (sans admin).
func Collect(h model.Host) *model.Firewall {
	out := &model.Firewall{}
	err := win.WithCOM(func() error {
		pol, err := win.NewObject("HNetCfg.FwPolicy2")
		if err != nil {
			return err
		}
		defer pol.Release()
		current, _ := pol.Int("CurrentProfileTypes")
		for _, p := range profileDefs {
			fp := model.FWProfile{Name: p.name, Active: current&int64(p.bit) != 0}
			fp.Enabled, _ = pol.Bool("FirewallEnabled", p.bit)
			if a, ok := pol.Int("DefaultInboundAction", p.bit); ok {
				fp.InboundAllow = a == actionAllow
			}
			// Une GPO l'emporte sur la configuration locale.
			if v := win.ReadValue(policyBase+p.key, "EnableFirewall"); v.Exists {
				fp.Enabled, fp.Policy = v.Uint(1) == 1, true
			}
			if v := win.ReadValue(policyBase+p.key, "DefaultInboundAction"); v.Exists {
				fp.InboundAllow, fp.Policy = v.Uint(1) == 0, true // 0 = autoriser dans la stratégie
			}
			out.Profiles = append(out.Profiles, fp)
		}
		rules, err := pol.Obj("Rules")
		if err != nil {
			return err
		}
		defer rules.Release()
		out.Rules = []model.FWRule{}
		return rules.ForEach(func(r *win.Disp) error {
			en, _ := r.Bool("Enabled")
			dir, _ := r.Int("Direction")
			act, _ := r.Int("Action")
			if !en || dir != dirIn || act != actionAllow {
				return nil
			}
			prof, _ := r.Int("Profiles")
			proto, _ := r.Int("Protocol")
			fr := model.FWRule{Name: r.Str("Name"), Grouping: r.Str("Grouping"), Profiles: Profiles(prof), Protocol: int(proto),
				LocalPorts: r.Str("LocalPorts"), Remote: r.Str("RemoteAddresses"), Application: r.Str("ApplicationName"), Service: r.Str("ServiceName"), AppPackage: r.Str("LocalAppPackageId")}
			if app := win.ExpandEnv(fr.Application); app != "" && strings.Contains(app, `\`) {
				a := win.CheckACL(services.Dir(app), win.KindDirReplace)
				if !a.Writable() {
					a = win.CheckACL(app, win.KindFile)
				}
				fr.App = &a
			}
			out.Rules = append(out.Rules, fr)
			return nil
		})
	})
	if err != nil {
		out.Gaps.Set("policy", model.GapError, err.Error())
	}
	if h.Role == model.RoleWorkstation {
		out.OtherFW = otherFirewalls()
	}
	return out
}

func otherFirewalls() []string {
	out := []string{}
	_ = win.WithCOM(func() error {
		return win.WbemQuery(`root\SecurityCenter2`, "SELECT displayName, productState FROM FirewallProduct", func(o *win.Disp) error {
			state, _ := o.Int("productState")
			if (state>>8)&0xF0 == 0x10 {
				out = append(out, o.Str("displayName"))
			}
			return nil
		})
	})
	return out
}
