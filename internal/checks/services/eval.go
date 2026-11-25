package services

import (
	"strconv"
	"strings"

	"github.com/maxb1906/aplomb/internal/checks"
	"github.com/maxb1906/aplomb/internal/model"
	"github.com/maxb1906/aplomb/internal/rules"
)

func init() {
	rules.Register("SVC-001", unquoted)
	rules.Register("SVC-002", writableBinary)
	rules.Register("SVC-003", writableKey)
	rules.Register("SVC-004", systemFromUserDir)
	rules.Register("SVC-005", spooler)
}

// list renvoie les services, ou l'Outcome à rendre s'ils manquent.
func list(c *rules.Ctx) ([]model.Service, *rules.Outcome) {
	s := c.Snap.Services
	if s == nil {
		o := rules.Missing(c.Snap.Gaps.Get("services"))
		return nil, &o
	}
	if s.List == nil {
		o := rules.Missing(s.Gaps.Get("list"))
		return nil, &o
	}
	return s.List, nil
}

func key(name string) string { return `HKLM:\SYSTEM\CurrentControlSet\Services\` + name }

func unquoted(c *rules.Ctx) rules.Outcome {
	svcs, o := list(c)
	if o != nil {
		return *o
	}
	var fs []rules.Finding
	for _, s := range svcs {
		if s.Quoted || s.InWindows || len(s.Hijack) == 0 || s.Start == model.StartDisabled {
			continue
		}
		lvl, writable := rules.Warning, []string{}
		for _, h := range s.Hijack {
			if h.Dir.Writable() {
				lvl = rules.Critical
				writable = append(writable, h.Dir.Path+" : "+checks.Principals(&h.Dir))
			}
		}
		fixed := `"` + s.Executable + `"`
		if s.Args != "" {
			fixed += " " + s.Args
		}
		ev := map[string]string{"image_path": s.ImagePath, "account": accountName(s)}
		if len(writable) > 0 {
			ev["writable_dirs"] = strings.Join(writable, " | ")
		}
		fs = append(fs, rules.Finding{Object: s.Name, Level: lvl, Evidence: ev,
			Params: map[string]string{"service": s.Name, "key": key(s.Name), "fixed": fixed}})
	}
	if len(fs) == 0 {
		return rules.Passed(map[string]string{"services": strconv.Itoa(len(svcs))})
	}
	return rules.Failed(fs...)
}

func writableBinary(c *rules.Ctx) rules.Outcome {
	svcs, o := list(c)
	if o != nil {
		return *o
	}
	var fs []rules.Finding
	for _, s := range svcs {
		if s.Start == model.StartDisabled {
			continue
		}
		// Binaire modifiable ou remplaçable : Critique. Dossier où l'on peut
		// seulement ajouter un fichier (DLL déposée à côté) : Attention.
		type target struct {
			acl   *model.PathACL
			path  string
			level string
		}
		var ts []target
		if s.Binary.Writable() {
			ts = append(ts, target{s.Binary, s.Binary.Path, rules.Critical})
		}
		if s.FolderReplace.Writable() {
			ts = append(ts, target{s.FolderReplace, s.FolderReplace.Path, rules.Critical})
		} else if s.Folder.Writable() {
			ts = append(ts, target{s.Folder, s.Folder.Path, rules.Warning})
		}
		for _, t := range ts {
			fs = append(fs, rules.Finding{Object: s.Name + " — " + t.path, Level: t.level,
				Evidence: map[string]string{"path": t.path, "writable_by": checks.Principals(t.acl), "account": accountName(s)},
				Params:   map[string]string{"service": s.Name, "path": t.path, "sids": checks.IcaclsSIDs(t.acl)}})
		}
	}
	if len(fs) == 0 {
		return rules.Passed(nil)
	}
	return rules.Failed(fs...)
}

func writableKey(c *rules.Ctx) rules.Outcome {
	svcs, o := list(c)
	if o != nil {
		return *o
	}
	var fs []rules.Finding
	for _, s := range svcs {
		if !s.Key.Writable() {
			continue
		}
		fs = append(fs, rules.Finding{Object: s.Name,
			Evidence: map[string]string{"key": s.Key.Path, "writable_by": checks.Principals(s.Key)},
			Params:   map[string]string{"service": s.Name, "key": key(s.Name), "sids": checks.PSList(s.Key)}})
	}
	if len(fs) == 0 {
		return rules.Passed(nil)
	}
	return rules.Failed(fs...)
}

func systemFromUserDir(c *rules.Ctx) rules.Outcome {
	svcs, o := list(c)
	if o != nil {
		return *o
	}
	var fs []rules.Finding
	for _, s := range svcs {
		if s.InWindows || !s.LocalSystem() || s.Start == model.StartDisabled || !UserWritableLocation(s.Executable) {
			continue
		}
		fs = append(fs, rules.Finding{Object: s.Name,
			Evidence: map[string]string{"executable": s.Executable, "account": accountName(s)},
			Params:   map[string]string{"service": s.Name, "path": s.Executable}})
	}
	if len(fs) == 0 {
		return rules.Passed(nil)
	}
	return rules.Failed(fs...)
}

func spooler(c *rules.Ctx) rules.Outcome {
	svcs, o := list(c)
	if o != nil {
		return *o
	}
	for _, s := range svcs {
		if !strings.EqualFold(s.Name, "Spooler") {
			continue
		}
		ev := map[string]string{"running": boolStr(s.Running), "printers": strings.Join(c.Snap.Services.Printers, ", ")}
		if !s.Running {
			return rules.Passed(ev)
		}
		if c.Role != model.RoleDC && len(c.Snap.Services.Printers) > 0 {
			return rules.Passed(ev)
		}
		return rules.Failed(rules.Finding{Evidence: ev, Params: map[string]string{"role": c.Role}})
	}
	return rules.Passed(map[string]string{"spooler": "absent"})
}

func accountName(s model.Service) string {
	if s.Account == "" {
		return "LocalSystem"
	}
	return s.Account
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}
