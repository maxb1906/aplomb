package bitlocker

import (
	"strconv"
	"strings"

	"github.com/maxb1906/aplomb/internal/model"
	"github.com/maxb1906/aplomb/internal/rules"
)

func init() {
	rules.Register("BDE-001", osNotEncrypted)
	rules.Register("BDE-002", suspended)
	rules.Register("BDE-003", tpmOnly)
	rules.Register("BDE-004", noRecovery)
	rules.Register("BDE-005", dataNotEncrypted)
	rules.Register("BDE-006", backupNotEnforced)
}

func volumes(c *rules.Ctx) ([]model.Volume, *rules.Outcome) {
	b := c.Snap.BitLocker
	if b == nil {
		o := rules.Missing(c.Snap.Gaps.Get("bitlocker"))
		return nil, &o
	}
	if b.Volumes == nil {
		o := rules.Missing(b.Gaps.Get("volumes"))
		return nil, &o
	}
	return b.Volumes, nil
}

func ev(v model.Volume) map[string]string {
	return map[string]string{"volume": v.Mount, "conversion": strconv.Itoa(v.Conversion), "protection": strconv.Itoa(v.Protection), "protectors": strings.Join(v.Protectors, ",")}
}

func params(c *rules.Ctx, v model.Volume) map[string]string {
	p := map[string]string{"mount": v.Mount, "join": c.Snap.Host.JoinType, "entra": ""}
	if c.Snap.Host.EntraJoined {
		p["entra"] = "1"
	}
	return p
}

func osVolume(vs []model.Volume) (model.Volume, bool) {
	for _, v := range vs {
		if v.Type == model.VolumeOS {
			return v, true
		}
	}
	return model.Volume{}, false
}

func portable(c *rules.Ctx) bool { return c.Snap.Host.Portable != nil && *c.Snap.Host.Portable }

func osNotEncrypted(c *rules.Ctx) rules.Outcome {
	vs, o := volumes(c)
	if o != nil {
		return *o
	}
	v, ok := osVolume(vs)
	if !ok {
		return rules.NA("absent")
	}
	if v.Encrypted() {
		return rules.Passed(ev(v))
	}
	lvl := rules.Warning
	if portable(c) {
		lvl = rules.Critical
	}
	return rules.Failed(rules.Finding{Object: v.Mount, Level: lvl, Evidence: ev(v), Params: params(c, v)})
}

func suspended(c *rules.Ctx) rules.Outcome {
	vs, o := volumes(c)
	if o != nil {
		return *o
	}
	var fs []rules.Finding
	for _, v := range vs {
		if v.Type != model.VolumeRemovable && (v.Conversion == 1 || v.Conversion == 4) && v.Protection == 0 {
			fs = append(fs, rules.Finding{Object: v.Mount, Evidence: ev(v), Params: params(c, v)})
		}
	}
	if len(fs) == 0 {
		return rules.Passed(nil)
	}
	return rules.Failed(fs...)
}

func tpmOnly(c *rules.Ctx) rules.Outcome {
	if !portable(c) {
		return rules.NA("not_portable")
	}
	vs, o := volumes(c)
	if o != nil {
		return *o
	}
	v, ok := osVolume(vs)
	if !ok || !v.Encrypted() {
		return rules.NA("not_encrypted")
	}
	if !v.ProtectorsKnown {
		return rules.Missing(c.Snap.BitLocker.Gaps.Get("protectors"))
	}
	if v.Has("tpm") && !v.Has("tpm_pin", "tpm_key", "tpm_pin_key") {
		return rules.Failed(rules.Finding{Object: v.Mount, Evidence: ev(v), Params: params(c, v)})
	}
	return rules.Passed(ev(v))
}

func noRecovery(c *rules.Ctx) rules.Outcome {
	vs, o := volumes(c)
	if o != nil {
		return *o
	}
	var fs []rules.Finding
	unknown := false
	for _, v := range vs {
		if v.Type == model.VolumeRemovable || !v.Encrypted() {
			continue
		}
		if !v.ProtectorsKnown {
			unknown = true
			continue
		}
		if !v.Has("recovery_password") {
			fs = append(fs, rules.Finding{Object: v.Mount, Evidence: ev(v), Params: params(c, v)})
		}
	}
	if len(fs) > 0 {
		return rules.Failed(fs...)
	}
	if unknown {
		return rules.Missing(c.Snap.BitLocker.Gaps.Get("protectors"))
	}
	return rules.Passed(nil)
}

func dataNotEncrypted(c *rules.Ctx) rules.Outcome {
	vs, o := volumes(c)
	if o != nil {
		return *o
	}
	var fs []rules.Finding
	n := 0
	for _, v := range vs {
		if v.Type != model.VolumeData || v.Mount == "" || strings.HasPrefix(v.Mount, `\\?\`) {
			continue // les volumes sans lettre (récupération, EFI) ne sont pas concernés
		}
		n++
		if !v.Encrypted() {
			fs = append(fs, rules.Finding{Object: v.Mount, Evidence: ev(v), Params: params(c, v)})
		}
	}
	if n == 0 {
		return rules.NA("no_data_volume")
	}
	if len(fs) == 0 {
		return rules.Passed(nil)
	}
	return rules.Failed(fs...)
}

func backupNotEnforced(c *rules.Ctx) rules.Outcome {
	if !c.Snap.Host.Joined() {
		return rules.NA("not_joined")
	}
	vs, o := volumes(c)
	if o != nil {
		return *o
	}
	v, ok := osVolume(vs)
	if !ok || !v.Encrypted() {
		return rules.NA("not_encrypted")
	}
	if c.Snap.BitLocker.BackupPolicy {
		return rules.Passed(map[string]string{"backup_policy": "true"})
	}
	return rules.Failed(rules.Finding{Object: v.Mount, Evidence: map[string]string{"backup_policy": "false"}, Params: params(c, v)})
}
