package host

import (
	"os"
	"os/user"
	"runtime"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/maxb1906/aplomb/internal/model"
	"github.com/maxb1906/aplomb/internal/win"
)

const ntCurrentVersion = `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion`

// Collect lit le contexte de la machine. Rien ici n'exige les droits admin.
func Collect() model.Host {
	h := model.Host{Arch: arch(), JoinType: "unknown", Firmware: "unknown"}
	if name, err := windows.ComputerName(); err == nil {
		h.Name = name
	} else {
		h.Name, _ = os.Hostname()
	}

	h.OS = win.ReadString(ntCurrentVersion, "ProductName")
	h.Edition = win.ReadString(ntCurrentVersion, "EditionID")
	h.DisplayVersion = win.ReadString(ntCurrentVersion, "DisplayVersion")
	if h.DisplayVersion == "" {
		h.DisplayVersion = win.ReadString(ntCurrentVersion, "ReleaseId")
	}
	h.Build = win.ReadString(ntCurrentVersion, "CurrentBuild")
	if h.Build == "" {
		h.Build = win.ReadString(ntCurrentVersion, "CurrentBuildNumber")
	}
	h.UBR = win.ReadValue(ntCurrentVersion, "UBR").Uint(0)
	h.InstallationType = win.ReadString(ntCurrentVersion, "InstallationType")
	h.OS = FixProductName(h.OS, h.Build)
	h.ProductType = win.ReadString(`HKLM\SYSTEM\CurrentControlSet\Control\ProductOptions`, "ProductType")
	h.Role = RoleFromProductType(h.ProductType)

	joinInfo(&h)
	entraInfo(&h)

	if u, err := user.Current(); err == nil {
		h.User = u.Username
	}
	h.Elevated = windows.GetCurrentProcessToken().IsElevated()

	firmware(&h)
	tpm(&h)
	portable(&h)
	lastUpdate(&h)
	return h
}

func arch() string {
	if a := os.Getenv("PROCESSOR_ARCHITEW6432"); a != "" {
		return strings.ToLower(a)
	}
	if a := os.Getenv("PROCESSOR_ARCHITECTURE"); a != "" {
		return strings.ToLower(a)
	}
	return runtime.GOARCH
}

func joinInfo(h *model.Host) {
	var name *uint16
	var status uint32
	if err := windows.NetGetJoinInformation(nil, &name, &status); err != nil {
		h.Gaps.Set("join", model.GapError, err.Error())
		return
	}
	defer windows.NetApiBufferFree((*byte)(unsafe.Pointer(name)))
	n := windows.UTF16PtrToString(name)
	switch status {
	case windows.NetSetupDomainName:
		h.JoinType, h.Domain = "domain", n
	case windows.NetSetupWorkgroupName:
		h.JoinType, h.Domain = "workgroup", n
	}
	// Nom DNS du domaine, plus parlant que le nom NetBIOS.
	if h.JoinType == "domain" {
		if d := win.ReadString(`HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters`, "Domain"); d != "" {
			h.Domain = d
		}
	}
}

func entraInfo(h *model.Host) {
	const base = `HKLM\SYSTEM\CurrentControlSet\Control\CloudDomainJoin`
	subs, err := win.SubKeys(base + `\JoinInfo`)
	if err != nil || len(subs) == 0 {
		return
	}
	h.EntraJoined = true
	if tid := win.ReadString(base+`\JoinInfo\`+subs[0], "TenantId"); tid != "" {
		h.EntraTenant = win.ReadString(base+`\TenantInfo\`+tid, "DisplayName")
		if h.EntraTenant == "" {
			h.EntraTenant = tid
		}
	}
}

func firmware(h *model.Host) {
	proc := windows.NewLazySystemDLL("kernel32.dll").NewProc("GetFirmwareType")
	if proc.Find() == nil {
		var ft uint32
		if r, _, _ := proc.Call(uintptr(unsafe.Pointer(&ft))); r != 0 {
			switch ft {
			case 1:
				h.Firmware = "bios"
			case 2:
				h.Firmware = "uefi"
			}
		}
	}
	if h.Firmware == "bios" {
		h.SecureBoot = model.Bool(false)
		return
	}
	v := win.ReadValue(`HKLM\SYSTEM\CurrentControlSet\Control\SecureBoot\State`, "UEFISecureBootEnabled")
	if v.Exists {
		h.SecureBoot = model.Bool(v.Uint(0) == 1)
	} else {
		h.Gaps.Set("secure_boot", model.GapError, "UEFISecureBootEnabled not found")
	}
}

// tpm interroge TBS (Tbsi_GetDeviceInfo), accessible sans droits admin.
func tpm(h *model.Host) {
	proc := windows.NewLazySystemDLL("tbs.dll").NewProc("Tbsi_GetDeviceInfo")
	if proc.Find() != nil {
		h.Gaps.Set("tpm", model.GapAbsent, "tbs.dll")
		return
	}
	var info struct{ StructVersion, TPMVersion, InterfaceType, ImpRevision uint32 }
	r, _, _ := proc.Call(unsafe.Sizeof(info), uintptr(unsafe.Pointer(&info)))
	switch uint32(r) {
	case 0:
		h.TPMPresent = model.Bool(true)
		switch info.TPMVersion {
		case 1:
			h.TPMVersion = "1.2"
		case 2:
			h.TPMVersion = "2.0"
		}
	case 0x8028400F: // TBS_E_TPM_NOT_FOUND
		h.TPMPresent = model.Bool(false)
	default:
		h.Gaps.Set("tpm", model.GapError, "Tbsi_GetDeviceInfo")
	}
}

func portable(h *model.Host) {
	var enc []struct{ ChassisTypes []uint16 }
	if err := win.WMI(`root\CIMV2`, "SELECT ChassisTypes FROM Win32_SystemEnclosure", &enc); err != nil {
		h.Gaps.Set("portable", model.GapError, err.Error())
		return
	}
	p := false
	for _, e := range enc {
		p = p || PortableChassis(e.ChassisTypes)
	}
	if !p {
		var bat []struct{ DeviceID string }
		if win.WMI(`root\CIMV2`, "SELECT DeviceID FROM Win32_Battery", &bat) == nil && len(bat) > 0 && h.Role == model.RoleWorkstation {
			p = true
		}
	}
	h.Portable = model.Bool(p)
}

func lastUpdate(h *model.Host) {
	var qfe []struct{ HotFixID, InstalledOn string }
	if err := win.WMI(`root\CIMV2`, "SELECT HotFixID, InstalledOn FROM Win32_QuickFixEngineering", &qfe); err != nil {
		h.Gaps.Set("last_update", model.GapError, err.Error())
		return
	}
	var best time.Time
	for _, q := range qfe {
		if t, ok := ParseQFEDate(q.InstalledOn); ok && t.After(best) {
			best, h.LastUpdateKB = t, q.HotFixID
		}
	}
	if best.IsZero() {
		h.Gaps.Set("last_update", model.GapError, "no dated hotfix")
		return
	}
	h.LastUpdate = &best
}
