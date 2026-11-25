package smb

import (
	"strconv"
	"strings"

	"github.com/maxb1906/aplomb/internal/checks"
	"github.com/maxb1906/aplomb/internal/model"
	"github.com/maxb1906/aplomb/internal/rules"
)

func init() {
	rules.Register("SMB-001", shareWrite)
	rules.Register("SMB-002", shareRead)
	rules.Register("SMB-003", serverSMB1)
	rules.Register("SMB-004", clientSMB1)
	rules.Register("SMB-005", signing)
	rules.Register("SMB-006", insecureGuest)
}

func section(c *rules.Ctx) (*model.SMB, *rules.Outcome) {
	s := c.Snap.SMB
	if s == nil {
		o := rules.Missing(c.Snap.Gaps.Get("smb"))
		return nil, &o
	}
	return s, nil
}

// userShares renvoie les partages de fichiers non administratifs.
func userShares(c *rules.Ctx) ([]model.Share, *rules.Outcome) {
	s, o := section(c)
	if o != nil {
		return nil, o
	}
	if s.Shares == nil {
		o := rules.Missing(s.Gaps.Get("shares"))
		return nil, &o
	}
	var out []model.Share
	for _, sh := range s.Shares {
		if !sh.Special && sh.Type&0xFF == 0 && !strings.EqualFold(sh.Name, "IPC$") {
			out = append(out, sh)
		}
	}
	return out, nil
}

// ntfsAllows : le dossier partagé accorde aussi le droit à un groupe non admin
// (l'accès effectif est le plus restrictif des droits de partage et NTFS).
func ntfsAllows(a *model.PathACL) bool { return a == nil || !a.Exists || a.Writable() }

func shareCheck(c *rules.Ctx, write bool) rules.Outcome {
	shares, o := userShares(c)
	if o != nil {
		return *o
	}
	var fs []rules.Finding
	unknown := false
	for _, sh := range shares {
		if !write && readableByDesign(sh.Name) {
			continue
		}
		if !sh.ACLKnown {
			unknown = true
			continue
		}
		for _, a := range sh.Access {
			var hit bool
			if write {
				hit = a.Write && ntfsAllows(sh.NTFSWrite)
			} else {
				// Lecture seule (l'écriture effective relève de SMB-001).
				hit = a.Read && ntfsAllows(sh.NTFSRead) && !(a.Write && ntfsAllows(sh.NTFSWrite))
			}
			if !hit {
				continue
			}
			ev := map[string]string{"path": sh.Path, "share_read": strconv.FormatBool(a.Read), "share_write": strconv.FormatBool(a.Write)}
			if sh.NTFSWrite != nil {
				ev["ntfs_write"] = checks.Principals(sh.NTFSWrite)
			}
			name := a.Name
			if name == "" {
				name = a.SID
			}
			fs = append(fs, rules.Finding{Object: sh.Name + " — " + name, Evidence: ev,
				Params: map[string]string{"share": sh.Name, "sid": a.SID, "path": sh.Path}})
		}
	}
	if len(fs) > 0 {
		return rules.Failed(fs...)
	}
	if unknown {
		return rules.Unchecked(model.Gap{Reason: model.GapAdmin, Detail: "share ACL"})
	}
	return rules.Passed(map[string]string{"shares": strconv.Itoa(len(shares))})
}

// readableByDesign : partages que Windows rend lisibles par tous (SYSVOL et
// NETLOGON d'un DC, pilotes d'impression). Leur écriture reste contrôlée.
func readableByDesign(name string) bool {
	switch strings.ToUpper(name) {
	case "SYSVOL", "NETLOGON", "PRINT$":
		return true
	}
	return false
}

func shareWrite(c *rules.Ctx) rules.Outcome { return shareCheck(c, true) }
func shareRead(c *rules.Ctx) rules.Outcome  { return shareCheck(c, false) }

func serverSMB1(c *rules.Ctx) rules.Outcome {
	s, o := section(c)
	if o != nil {
		return *o
	}
	if s.Server == nil || s.Server.SMB1 == nil {
		return rules.Missing(s.Gaps.Get("server"))
	}
	ev := map[string]string{"smb1": strconv.FormatBool(*s.Server.SMB1), "source": s.Server.Source}
	if !*s.Server.SMB1 {
		return rules.Passed(ev)
	}
	return rules.Failed(rules.Finding{Evidence: ev})
}

func clientSMB1(c *rules.Ctx) rules.Outcome {
	s, o := section(c)
	if o != nil {
		return *o
	}
	if s.Client == nil || s.Client.SMB1 == nil {
		return rules.Missing(s.Gaps.Get("client"))
	}
	ev := map[string]string{"mrxsmb10": strconv.FormatBool(*s.Client.SMB1)}
	if !*s.Client.SMB1 {
		return rules.Passed(ev)
	}
	return rules.Failed(rules.Finding{Evidence: ev})
}

func signing(c *rules.Ctx) rules.Outcome {
	s, o := section(c)
	if o != nil {
		return *o
	}
	if s.Server == nil || s.Server.RequireSigning == nil {
		return rules.Missing(s.Gaps.Get("server"))
	}
	ev := map[string]string{"require_signing": strconv.FormatBool(*s.Server.RequireSigning), "source": s.Server.Source}
	if *s.Server.RequireSigning {
		return rules.Passed(ev)
	}
	lvl := rules.Warning
	if c.Role == model.RoleDC {
		lvl = rules.Critical
	}
	return rules.Failed(rules.Finding{Level: lvl, Evidence: ev})
}

func insecureGuest(c *rules.Ctx) rules.Outcome {
	s, o := section(c)
	if o != nil {
		return *o
	}
	if s.Client == nil {
		return rules.Missing(s.Gaps.Get("client"))
	}
	ev := map[string]string{"allow_insecure_guest_auth": strconv.FormatBool(s.Client.InsecureGuest)}
	if !s.Client.InsecureGuest {
		return rules.Passed(ev)
	}
	return rules.Failed(rules.Finding{Evidence: ev, GPO: s.Client.InsecureGuestPolicy})
}
