package tasks

import (
	"os"
	"strings"

	"golang.org/x/sys/windows"

	"github.com/maxb1906/aplomb/internal/checks/services"
	"github.com/maxb1906/aplomb/internal/model"
	"github.com/maxb1906/aplomb/internal/win"
)

const (
	taskEnumHidden    = 1
	taskActionExec    = 0
	taskRunLevelHigh  = 1
	adminsGroupSID    = "S-1-5-32-544"
	maxTasks          = 5000
	maxFoldersVisited = 2000
)

// Collect énumère les tâches via l'API COM du Planificateur de tâches 2.0.
func Collect(elevated bool) *model.Tasks {
	out := &model.Tasks{Partial: !elevated}
	windir := os.Getenv("SystemRoot")
	if windir == "" {
		windir = `C:\Windows`
	}
	err := win.WithCOM(func() error {
		svc, err := win.NewObject("Schedule.Service")
		if err != nil {
			return err
		}
		defer svc.Release()
		if _, err := svc.Call("Connect"); err != nil {
			return err
		}
		root, err := svc.CallObj("GetFolder", `\`)
		if err != nil {
			return err
		}
		defer root.Release()
		visited := 0
		var walk func(f *win.Disp)
		walk = func(f *win.Disp) {
			visited++
			if visited > maxFoldersVisited || len(out.List) > maxTasks {
				return
			}
			if tasks, err := f.CallObj("GetTasks", taskEnumHidden); err == nil {
				_ = tasks.ForEach(func(t *win.Disp) error {
					if task, ok := readTask(t, windir); ok {
						out.List = append(out.List, task)
					} else {
						out.Unreadable++
					}
					return nil
				})
				tasks.Release()
			}
			if subs, err := f.CallObj("GetFolders", 0); err == nil {
				_ = subs.ForEach(func(sub *win.Disp) error { walk(sub); return nil })
				subs.Release()
			}
		}
		walk(root)
		return nil
	})
	if err != nil {
		out.List = nil
		out.Gaps.Set("list", model.GapError, err.Error())
	} else if out.List == nil {
		out.List = []model.Task{}
	}
	return out
}

func readTask(t *win.Disp, windir string) (model.Task, bool) {
	task := model.Task{Path: t.Str("Path"), Name: t.Str("Name")}
	if i := strings.LastIndex(task.Path, `\`); i >= 0 {
		task.Folder = task.Path[:i+1]
	}
	task.Enabled, _ = t.Bool("Enabled")
	def, err := t.Obj("Definition")
	if err != nil {
		return task, false
	}
	defer def.Release()
	if ri, err := def.Obj("RegistrationInfo"); err == nil {
		task.Author = ri.Str("Author")
		ri.Release()
	}
	if st, err := def.Obj("Settings"); err == nil {
		task.Hidden, _ = st.Bool("Hidden")
		st.Release()
	}
	if p, err := def.Obj("Principal"); err == nil {
		task.UserID, task.GroupID = p.Str("UserId"), p.Str("GroupId")
		if rl, ok := p.Int("RunLevel"); ok {
			task.RunLevel = int(rl)
		}
		p.Release()
	}
	task.PrincipalSID = toSID(task.UserID)
	group := toSID(task.GroupID)
	switch {
	case task.PrincipalSID == "S-1-5-18", task.PrincipalSID == "S-1-5-19", task.PrincipalSID == "S-1-5-20":
		task.Privileged = true
	case task.RunLevel == taskRunLevelHigh, group == adminsGroupSID, strings.HasSuffix(task.PrincipalSID, "-500"):
		task.Privileged = true
	}
	if acts, err := def.Obj("Actions"); err == nil {
		_ = acts.ForEach(func(a *win.Disp) error {
			if typ, _ := a.Int("Type"); typ != taskActionExec {
				return nil
			}
			task.Actions = append(task.Actions, readAction(a, windir))
			return nil
		})
		acts.Release()
	}
	return task, true
}

func readAction(a *win.Disp, windir string) model.TaskAction {
	act := model.TaskAction{Path: a.Str("Path"), Args: a.Str("Arguments"), WorkDir: a.Str("WorkingDirectory")}
	p := strings.Trim(win.ExpandEnv(act.Path), `"`)
	act.Resolved = p
	for _, c := range ResolveCandidates(p, windir) {
		if _, err := os.Stat(c); err == nil {
			act.Resolved, act.Exists = c, true
			break
		}
	}
	if act.Exists {
		f := win.CheckACL(act.Resolved, win.KindFile)
		act.File = &f
		r := win.CheckACL(services.Dir(act.Resolved), win.KindDirReplace)
		act.Replace = &r
	} else if strings.Contains(act.Resolved, `\`) {
		c := win.CheckACL(services.Dir(act.Resolved), win.KindDirCreate)
		act.Create = &c
	}
	if s := ScriptFromArgs(act.Resolved, win.ExpandEnv(act.Args)); s != "" {
		if !strings.Contains(s, `\`) && act.WorkDir != "" {
			s = strings.TrimRight(win.ExpandEnv(act.WorkDir), `\`) + `\` + s
		}
		act.Script = s
		if _, err := os.Stat(s); err == nil {
			act.ScriptExists = true
			f := win.CheckACL(s, win.KindFile)
			act.ScriptFile = &f
			r := win.CheckACL(services.Dir(s), win.KindDirReplace)
			act.ScriptReplace = &r
		}
	}
	return act
}

// toSID convertit un compte (« SYSTEM », « AUTORITE NT\Système », SID) en SID.
func toSID(account string) string {
	if account == "" {
		return ""
	}
	if strings.HasPrefix(account, "S-1-") {
		return account
	}
	switch strings.ToUpper(account) {
	case "SYSTEM", `NT AUTHORITY\SYSTEM`, "LOCALSYSTEM":
		return "S-1-5-18"
	}
	sid, _, _, err := windows.LookupSID("", account)
	if err != nil {
		return ""
	}
	return sid.String()
}
