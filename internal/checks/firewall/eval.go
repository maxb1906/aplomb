package firewall

import (
	"strconv"
	"strings"

	"github.com/maxb1906/aplomb/internal/checks"
	"github.com/maxb1906/aplomb/internal/model"
	"github.com/maxb1906/aplomb/internal/rules"
)

func init() {
	rules.Register("FW-001", profileOff)
	rules.Register("FW-002", inboundAllow)
	rules.Register("FW-003", anyAny)
	rules.Register("FW-004", sensitivePublic)
	rules.Register("FW-005", writableProgram)
}

func section(c *rules.Ctx) (*model.Firewall, *rules.Outcome) {
	f := c.Snap.Firewall
	if f == nil {
		o := rules.Missing(c.Snap.Gaps.Get("firewall"))
		return nil, &o
	}
	if len(f.OtherFW) > 0 {
		o := rules.NA("other_fw", strings.Join(f.OtherFW, ", "))
		return nil, &o
	}
	if f.Profiles == nil {
		o := rules.Missing(f.Gaps.Get("policy"))
		return nil, &o
	}
	return f, nil
}

func profileEv(p model.FWProfile) map[string]string {
	return map[string]string{"profile": p.Name, "enabled": strconv.FormatBool(p.Enabled), "inbound_allow": strconv.FormatBool(p.InboundAllow), "active": strconv.FormatBool(p.Active)}
}

func profileOff(c *rules.Ctx) rules.Outcome {
	f, o := section(c)
	if o != nil {
		return *o
	}
	var fs []rules.Finding
	for _, p := range f.Profiles {
		if !p.Enabled {
			fs = append(fs, rules.Finding{Object: p.Name, Evidence: profileEv(p), GPO: p.Policy, Params: map[string]string{"profile": p.Name}})
		}
	}
	if len(fs) == 0 {
		return rules.Passed(nil)
	}
	return rules.Failed(fs...)
}

func inboundAllow(c *rules.Ctx) rules.Outcome {
	f, o := section(c)
	if o != nil {
		return *o
	}
	var fs []rules.Finding
	for _, p := range f.Profiles {
		if p.Enabled && p.InboundAllow {
			fs = append(fs, rules.Finding{Object: p.Name, Evidence: profileEv(p), GPO: p.Policy, Params: map[string]string{"profile": p.Name}})
		}
	}
	if len(fs) == 0 {
		return rules.Passed(nil)
	}
	return rules.Failed(fs...)
}

func ruleEv(r model.FWRule) map[string]string {
	ev := map[string]string{"profiles": strings.Join(r.Profiles, ","), "protocol": strconv.Itoa(r.Protocol), "local_ports": r.LocalPorts, "remote": r.Remote}
	if r.Application != "" {
		ev["application"] = r.Application
	}
	if r.Service != "" {
		ev["service"] = r.Service
	}
	return ev
}

// tcpOrUDP : protocoles concernés par les ports (ICMP, GRE… n'en ont pas).
func tcpOrUDP(p int) bool { return p == 6 || p == 17 || p == 256 || p == 0 }

func anyAny(c *rules.Ctx) rules.Outcome {
	f, o := section(c)
	if o != nil {
		return *o
	}
	var fs []rules.Finding
	for _, r := range f.Rules {
		if !tcpOrUDP(r.Protocol) || !AnyPort(r.LocalPorts) || !AnyAddress(r.Remote) || r.Application != "" || r.Service != "" || storeApp(r) {
			continue
		}
		fs = append(fs, rules.Finding{Object: r.Name, Evidence: ruleEv(r), Params: map[string]string{"rule": r.Name}})
	}
	if len(fs) == 0 {
		return rules.Passed(map[string]string{"inbound_allow_rules": strconv.Itoa(len(f.Rules))})
	}
	return rules.Failed(fs...)
}

// storeApp : règle d'une application du Store, limitée à son package (son nom
// est une ressource « @{Package?ms-resource://…} »).
func storeApp(r model.FWRule) bool {
	return r.AppPackage != "" || strings.HasPrefix(r.Name, "@{")
}

func sensitivePublic(c *rules.Ctx) rules.Outcome {
	f, o := section(c)
	if o != nil {
		return *o
	}
	var fs []rules.Finding
	for _, r := range f.Rules {
		if !r.HasProfile("Public") || !AnyAddress(r.Remote) || !tcpOrUDP(r.Protocol) {
			continue
		}
		ports := MatchSensitive(r.LocalPorts)
		if len(ports) == 0 {
			continue
		}
		var names []string
		for _, p := range ports {
			names = append(names, strconv.Itoa(p)+" "+SensitivePorts[p])
		}
		ev := ruleEv(r)
		ev["sensitive"] = strings.Join(names, ", ")
		fs = append(fs, rules.Finding{Object: r.Name + " (" + strings.Join(names, ", ") + ")", Evidence: ev, Params: map[string]string{"rule": r.Name}})
	}
	if len(fs) == 0 {
		return rules.Passed(nil)
	}
	return rules.Failed(fs...)
}

func writableProgram(c *rules.Ctx) rules.Outcome {
	f, o := section(c)
	if o != nil {
		return *o
	}
	var fs []rules.Finding
	seen := map[string]bool{}
	for _, r := range f.Rules {
		if !r.App.Writable() || seen[strings.ToLower(r.App.Path)] {
			continue
		}
		seen[strings.ToLower(r.App.Path)] = true
		ev := ruleEv(r)
		ev["writable_by"] = checks.Principals(r.App)
		fs = append(fs, rules.Finding{Object: r.Name + " — " + r.Application, Evidence: ev,
			Params: map[string]string{"rule": r.Name, "path": r.App.Path, "sids": checks.IcaclsSIDs(r.App)}})
	}
	if len(fs) == 0 {
		return rules.Passed(nil)
	}
	return rules.Failed(fs...)
}
