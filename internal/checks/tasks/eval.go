package tasks

import (
	"strings"

	"github.com/maxb1906/aplomb/internal/checks"
	"github.com/maxb1906/aplomb/internal/model"
	"github.com/maxb1906/aplomb/internal/rules"
)

func init() {
	rules.Register("TSK-001", writableTarget)
	rules.Register("TSK-002", riskyLocation)
	rules.Register("TSK-003", suspiciousCmd)
	rules.Register("TSK-004", hiddenOrAnonymous)
	rules.Register("TSK-005", orphan)
}

func list(c *rules.Ctx) (*model.Tasks, *rules.Outcome) {
	t := c.Snap.Tasks
	if t == nil {
		o := rules.Missing(c.Snap.Gaps.Get("tasks"))
		return nil, &o
	}
	if t.List == nil {
		o := rules.Missing(t.Gaps.Get("list"))
		return nil, &o
	}
	return t, nil
}

// done renvoie Pass (avec mention « partiel » sans admin) ou Fail.
func done(t *model.Tasks, fs []rules.Finding) rules.Outcome {
	if len(fs) > 0 {
		return rules.Failed(fs...)
	}
	o := rules.Passed(nil)
	if t.Partial {
		o.Note = "partial_tasks"
	}
	return o
}

func params(t model.Task) map[string]string {
	return map[string]string{"task": t.Path, "folder": t.Folder, "name": t.Name}
}

func microsoft(t model.Task) bool { return strings.HasPrefix(strings.ToLower(t.Path), `\microsoft\`) }

func writableTarget(c *rules.Ctx) rules.Outcome {
	ts, o := list(c)
	if o != nil {
		return *o
	}
	var fs []rules.Finding
	for _, t := range ts.List {
		if !t.Privileged || !t.Enabled {
			continue
		}
		for _, a := range t.Actions {
			for _, acl := range []*model.PathACL{a.File, a.Replace, a.Create, a.ScriptFile, a.ScriptReplace} {
				if !acl.Writable() {
					continue
				}
				p := params(t)
				p["path"], p["sids"] = acl.Path, checks.IcaclsSIDs(acl)
				fs = append(fs, rules.Finding{Object: t.Path + " — " + acl.Path,
					Evidence: map[string]string{"run_as": runAs(t), "command": strings.TrimSpace(a.Path + " " + a.Args), "writable_by": checks.Principals(acl)},
					Params:   p})
			}
		}
	}
	return done(ts, fs)
}

func riskyLocation(c *rules.Ctx) rules.Outcome {
	ts, o := list(c)
	if o != nil {
		return *o
	}
	var fs []rules.Finding
	for _, t := range ts.List {
		if !t.Privileged || !t.Enabled {
			continue
		}
		for _, a := range t.Actions {
			hit := ""
			if RiskyLocation(a.Resolved, a.Replace.Writable() || a.Create.Writable()) {
				hit = a.Resolved
			} else if a.Script != "" && RiskyLocation(a.Script, a.ScriptReplace.Writable()) {
				hit = a.Script
			}
			if hit == "" {
				continue
			}
			p := params(t)
			p["path"] = hit
			fs = append(fs, rules.Finding{Object: t.Path, Evidence: map[string]string{"run_as": runAs(t), "path": hit}, Params: p})
			break
		}
	}
	return done(ts, fs)
}

func suspiciousCmd(c *rules.Ctx) rules.Outcome {
	ts, o := list(c)
	if o != nil {
		return *o
	}
	var fs []rules.Finding
	for _, t := range ts.List {
		for _, a := range t.Actions {
			if s := Suspicious(a.Resolved, a.Args); len(s) > 0 {
				fs = append(fs, rules.Finding{Object: t.Path,
					Evidence: map[string]string{"command": strings.TrimSpace(a.Path + " " + a.Args), "indicators": strings.Join(s, ", "), "run_as": runAs(t)},
					Params:   params(t)})
				break
			}
		}
	}
	return done(ts, fs)
}

func hiddenOrAnonymous(c *rules.Ctx) rules.Outcome {
	ts, o := list(c)
	if o != nil {
		return *o
	}
	var fs []rules.Finding
	for _, t := range ts.List {
		if microsoft(t) || (!t.Hidden && strings.TrimSpace(t.Author) != "") {
			continue
		}
		cmd := ""
		if len(t.Actions) > 0 {
			cmd = strings.TrimSpace(t.Actions[0].Path + " " + t.Actions[0].Args)
		}
		fs = append(fs, rules.Finding{Object: t.Path,
			Evidence: map[string]string{"hidden": boolStr(t.Hidden), "author": t.Author, "command": cmd, "run_as": runAs(t)},
			Params:   params(t)})
	}
	return done(ts, fs)
}

func orphan(c *rules.Ctx) rules.Outcome {
	ts, o := list(c)
	if o != nil {
		return *o
	}
	var fs []rules.Finding
	for _, t := range ts.List {
		for _, a := range t.Actions {
			if !a.Exists && a.Path != "" {
				fs = append(fs, rules.Finding{Object: t.Path,
					Evidence: map[string]string{"missing": a.Resolved, "enabled": boolStr(t.Enabled)},
					Params:   params(t)})
				break
			}
		}
	}
	return done(ts, fs)
}

func runAs(t model.Task) string {
	switch {
	case t.UserID != "":
		return t.UserID
	case t.GroupID != "":
		return t.GroupID
	}
	return t.PrincipalSID
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}
