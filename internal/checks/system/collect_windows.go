package system

import (
	"os"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/maxb1906/aplomb/internal/model"
	"github.com/maxb1906/aplomb/internal/win"
)

// Collect lit les paramètres de durcissement.
func Collect(h model.Host) *model.System {
	out := &model.System{Values: map[string]model.RegValue{}}
	for id, s := range Settings {
		out.Values[id] = win.ReadPolicy(s.Policy, s.Local, s.Name)
	}
	const netbt = `HKLM\SYSTEM\CurrentControlSet\Services\NetBT`
	out.NetBTDisabled = win.ReadValue(netbt, "Start").Uint(1) == 4
	if ifs, err := win.SubKeys(netbt + `\Parameters\Interfaces`); err == nil {
		for _, id := range ifs {
			v := win.ReadValue(netbt+`\Parameters\Interfaces\`+id, "NetbiosOptions")
			out.NetBIOS = append(out.NetBIOS, model.NetBIOSIface{ID: strings.TrimPrefix(id, "Tcpip_"), Options: int(v.Uint(0))})
		}
	}
	if h.Elevated {
		if p, err := lsassProtected(); err == nil {
			out.LSAProtected = &p
		} else {
			out.Gaps.Set("lsa", model.GapError, err.Error())
		}
	}
	out.CredentialGuard = readCredentialGuard(out)
	psv2 := out.Values["psv2_engine"].Str == "2.0" && psv2Files()
	out.PSv2 = &psv2
	return out
}

// lsassProtected lit le niveau de protection du processus lsass.exe.
func lsassProtected() (bool, error) {
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return false, err
	}
	defer windows.CloseHandle(snap)
	var e windows.ProcessEntry32
	e.Size = uint32(unsafe.Sizeof(e))
	var pid uint32
	for err = windows.Process32First(snap, &e); err == nil; err = windows.Process32Next(snap, &e) {
		if strings.EqualFold(windows.UTF16ToString(e.ExeFile[:]), "lsass.exe") {
			pid = e.ProcessID
			break
		}
	}
	if pid == 0 {
		return false, os.ErrNotExist
	}
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return false, err
	}
	defer windows.CloseHandle(h)
	proc := windows.NewLazySystemDLL("kernel32.dll").NewProc("GetProcessInformation")
	if proc.Find() != nil {
		return false, proc.Find()
	}
	const processProtectionLevelInfo = 7
	const protectionLevelNone = 0xFFFFFFFE
	var level uint32
	r, _, e2 := proc.Call(uintptr(h), processProtectionLevelInfo, uintptr(unsafe.Pointer(&level)), unsafe.Sizeof(level))
	if r == 0 {
		return false, e2
	}
	return level != protectionLevelNone, nil
}

// readCredentialGuard lit Win32_DeviceGuard.SecurityServicesRunning (1 = Credential Guard).
func readCredentialGuard(out *model.System) *bool {
	var running *bool
	err := win.WithCOM(func() error {
		return win.WbemQuery(`root\Microsoft\Windows\DeviceGuard`, "SELECT SecurityServicesRunning FROM Win32_DeviceGuard", func(o *win.Disp) error {
			svcs, ok := o.Ints("SecurityServicesRunning")
			if !ok {
				return nil
			}
			r := false
			for _, s := range svcs {
				if s == 1 {
					r = true
				}
			}
			running = &r
			return nil
		})
	})
	if err != nil {
		reason := model.GapError
		if win.IsNotFound(err) {
			reason = model.GapAbsent
		}
		out.Gaps.Set("credential_guard", reason, err.Error())
	}
	return running
}

// psv2Files vérifie la présence du moteur 2.0 dans le GAC .NET 2.
func psv2Files() bool {
	windir := os.Getenv("SystemRoot")
	if windir == "" {
		windir = `C:\Windows`
	}
	_, err := os.Stat(windir + `\assembly\GAC_MSIL\System.Management.Automation\1.0.0.0__31bf3856ad364e35\System.Management.Automation.dll`)
	return err == nil
}
