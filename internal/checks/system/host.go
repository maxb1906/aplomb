// Package system contient les contrôles de durcissement système (UAC, RDP,
// LLMNR, WDigest, LSA, mises à jour, Secure Boot…).
package system

import (
	"strconv"

	"github.com/maxb1906/aplomb/internal/rules"
)

func init() {
	rules.Register("SYS-012", lastUpdate)
	rules.Register("SYS-013", secureBoot)
}

func lastUpdate(c *rules.Ctx) rules.Outcome {
	h := c.Snap.Host
	if h.LastUpdate == nil {
		return rules.Missing(h.Gaps.Get("last_update"))
	}
	days := int(c.Now.Sub(*h.LastUpdate).Hours() / 24)
	ev := map[string]string{"last_update": h.LastUpdate.Format("2006-01-02"), "kb": h.LastUpdateKB, "days": strconv.Itoa(days)}
	if days <= 30 {
		return rules.Passed(ev)
	}
	lvl := rules.Warning
	if days > 60 {
		lvl = rules.Critical
	}
	return rules.Failed(rules.Finding{Level: lvl, Evidence: ev, Params: map[string]string{
		"date": h.LastUpdate.Format("2006-01-02"), "days": strconv.Itoa(days), "kb": h.LastUpdateKB,
	}})
}

func secureBoot(c *rules.Ctx) rules.Outcome {
	h := c.Snap.Host
	if h.SecureBoot == nil {
		return rules.Missing(h.Gaps.Get("secure_boot"))
	}
	ev := map[string]string{"firmware": h.Firmware, "secure_boot": strconv.FormatBool(*h.SecureBoot)}
	if *h.SecureBoot {
		return rules.Passed(ev)
	}
	return rules.Failed(rules.Finding{Evidence: ev, Params: map[string]string{"firmware": h.Firmware}})
}
