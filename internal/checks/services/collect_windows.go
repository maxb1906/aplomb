package services

import (
	"os"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/maxb1906/aplomb/internal/model"
	"github.com/maxb1906/aplomb/internal/win"
)

const servicesKey = `HKLM\SYSTEM\CurrentControlSet\Services`

// virtualPrinters ne comptent pas comme de « vraies » imprimantes.
var virtualPrinters = []string{"microsoft print to pdf", "microsoft xps document writer", "onenote", "fax", "send to onenote"}

// Collect lit la configuration des services dans le registre (lisible sans
// admin) et leur état via le gestionnaire de services.
func Collect() *model.Services {
	out := &model.Services{}
	windir := os.Getenv("SystemRoot")
	if windir == "" {
		windir = `C:\Windows`
	}
	names, err := win.SubKeys(servicesKey)
	if err != nil {
		out.Gaps.Set("list", model.GapError, err.Error())
		return out
	}
	running, display, stateErr := states()
	if stateErr != nil {
		out.Gaps.Set("state", model.GapError, stateErr.Error())
	}
	for _, name := range names {
		key := servicesKey + `\` + name
		typ := uint32(win.ReadValue(key, "Type").Uint(0))
		if typ&windows.SERVICE_WIN32 == 0 {
			continue // pilote
		}
		raw := win.ReadString(key, "ImagePath")
		if raw == "" {
			continue
		}
		expanded := win.ExpandEnv(raw)
		exe, args, quoted := ParseImagePath(expanded, windir)
		s := model.Service{
			Name: name, DisplayName: display[strings.ToLower(name)], ImagePath: raw, Executable: exe, Args: args, Quoted: quoted,
			Account: win.ReadString(key, "ObjectName"), Start: uint32(win.ReadValue(key, "Start").Uint(3)), Type: typ,
			Running: running[strings.ToLower(name)], InWindows: Under(exe, windir),
		}
		if s.DisplayName == "" {
			s.DisplayName = win.ReadString(key, "DisplayName")
		}
		if !quoted && strings.Contains(exe, " ") && !s.InWindows {
			for _, h := range UnquotedCandidates(exe) {
				s.Hijack = append(s.Hijack, model.HijackDir{Plant: h.Plant, Dir: win.CheckACL(h.Dir, win.KindDirCreate)})
			}
		}
		bin := win.CheckACL(exe, win.KindFile)
		s.Binary = &bin
		dir := win.CheckACL(Dir(exe), win.KindDirCreate)
		s.Folder = &dir
		rep := win.CheckACL(Dir(exe), win.KindDirReplace)
		s.FolderReplace = &rep
		k := win.CheckACL(key, win.KindKey)
		s.Key = &k
		out.List = append(out.List, s)
	}
	out.Printers = printers()
	return out
}

// states renvoie, par nom de service en minuscules, s'il tourne et son nom affiché.
func states() (map[string]bool, map[string]string, error) {
	running, display := map[string]bool{}, map[string]string{}
	h, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT|windows.SC_MANAGER_ENUMERATE_SERVICE)
	if err != nil {
		return running, display, err
	}
	defer windows.CloseServiceHandle(h)
	var needed, count, resume uint32
	buf := make([]byte, 256*1024)
	for {
		err = windows.EnumServicesStatusEx(h, windows.SC_ENUM_PROCESS_INFO, windows.SERVICE_WIN32, windows.SERVICE_STATE_ALL,
			&buf[0], uint32(len(buf)), &needed, &count, &resume, nil)
		if err != nil && err != windows.ERROR_MORE_DATA {
			return running, display, err
		}
		entries := unsafe.Slice((*windows.ENUM_SERVICE_STATUS_PROCESS)(unsafe.Pointer(&buf[0])), count)
		for _, e := range entries {
			n := strings.ToLower(windows.UTF16PtrToString(e.ServiceName))
			running[n] = e.ServiceStatusProcess.CurrentState == windows.SERVICE_RUNNING
			display[n] = windows.UTF16PtrToString(e.DisplayName)
		}
		if err == nil {
			return running, display, nil
		}
		if needed > uint32(len(buf)) {
			buf = make([]byte, needed)
		}
	}
}

func printers() []string {
	names, err := win.SubKeys(`HKLM\SYSTEM\CurrentControlSet\Control\Print\Printers`)
	if err != nil {
		return nil
	}
	var out []string
	for _, n := range names {
		low := strings.ToLower(n)
		virtual := false
		for _, v := range virtualPrinters {
			if strings.HasPrefix(low, v) {
				virtual = true
			}
		}
		if !virtual {
			out = append(out, n)
		}
	}
	return out
}
