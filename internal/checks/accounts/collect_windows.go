// Package accounts contient les contrôles des comptes et de la politique de
// mots de passe (§ 5.2).
package accounts

import (
	"fmt"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/maxb1906/aplomb/internal/model"
	"github.com/maxb1906/aplomb/internal/win"
)

var (
	netapi32                    = windows.NewLazySystemDLL("netapi32.dll")
	procNetUserModalsGet        = netapi32.NewProc("NetUserModalsGet")
	procNetLocalGroupGetMembers = netapi32.NewProc("NetLocalGroupGetMembers")
	samlib                      = windows.NewLazySystemDLL("samlib.dll")
	procSamConnect              = samlib.NewProc("SamConnect")
	procSamLookupDomain         = samlib.NewProc("SamLookupDomainInSamServer")
	procSamEnumDomains          = samlib.NewProc("SamEnumerateDomainsInSamServer")
	procSamOpenDomain           = samlib.NewProc("SamOpenDomain")
	procSamQueryInfoDomain      = samlib.NewProc("SamQueryInformationDomain")
	procSamFreeMemory           = samlib.NewProc("SamFreeMemory")
	procSamCloseHandle          = samlib.NewProc("SamCloseHandle")
)

const (
	timeqForever        = 0xFFFFFFFF
	ufAccountDisable    = 0x2
	ufPasswdNotReqd     = 0x20
	ufDontExpirePasswd  = 0x10000
	filterNormalAccount = 0x2
	errorMoreData       = 234
	maxPreferredLength  = 0xFFFFFFFF
)

// Collect lit la politique, les comptes locaux, les administrateurs et LAPS.
func Collect(h model.Host) *model.Accounts {
	out := &model.Accounts{}
	if p, err := policy(); err != nil {
		out.Gaps.Set("policy", model.GapError, err.Error())
	} else {
		out.Policy = p
	}
	if out.Policy != nil {
		if c, err := complexity(h.Name); err != nil {
			out.Gaps.Set("complexity", gapFor(err), err.Error())
		} else {
			out.Policy.Complexity = &c
		}
	}
	if u, err := users(h.Role == model.RoleDC); err != nil {
		out.Gaps.Set("users", gapFor(err), err.Error())
	} else {
		out.Users = u
	}
	if a, err := admins(); err != nil {
		out.Gaps.Set("admins", gapFor(err), err.Error())
	} else {
		out.Admins = a
	}
	out.LAPS = laps()
	return out
}

func gapFor(err error) string {
	if win.IsAccessDenied(err) {
		return model.GapAdmin
	}
	return model.GapError
}

func policy() (*model.PasswordPolicy, error) {
	var b0 *byte
	if r, _, _ := procNetUserModalsGet.Call(0, 0, uintptr(unsafe.Pointer(&b0))); r != 0 {
		return nil, fmt.Errorf("NetUserModalsGet(0) : %w", windows.Errno(r))
	}
	defer windows.NetApiBufferFree(b0)
	i0 := (*struct{ MinLen, MaxAge, MinAge, ForceLogoff, History uint32 })(unsafe.Pointer(b0))
	p := &model.PasswordPolicy{MinLength: int(i0.MinLen), MinAgeDays: int(i0.MinAge / 86400), History: int(i0.History)}
	if i0.MaxAge == timeqForever {
		p.MaxAgeDays = -1
	} else {
		p.MaxAgeDays = int(i0.MaxAge / 86400)
	}
	var b3 *byte
	if r, _, _ := procNetUserModalsGet.Call(0, 3, uintptr(unsafe.Pointer(&b3))); r == 0 {
		defer windows.NetApiBufferFree(b3)
		i3 := (*struct{ Duration, Window, Threshold uint32 })(unsafe.Pointer(b3))
		p.LockoutThreshold = int(i3.Threshold)
		p.LockoutDurationMin = int(i3.Duration / 60)
		p.LockoutWindowMin = int(i3.Window / 60)
	}
	return p, nil
}

// complexity lit PasswordProperties via l'API SAM (comme « net accounts »).
func complexity(computer string) (bool, error) {
	if err := procSamConnect.Find(); err != nil {
		return false, err
	}
	const (
		samServerConnect      = 0x1
		samServerLookupDomain = 0x20
		domainReadPwParams    = 0x1
		domainPasswordInfo    = 1
		domainPasswordComplex = 0x1
	)
	var oa struct {
		Length                   uint32
		RootDirectory            uintptr
		ObjectName               uintptr
		Attributes               uint32
		SecurityDescriptor       uintptr
		SecurityQualityOfService uintptr
	}
	oa.Length = uint32(unsafe.Sizeof(oa))
	var server uintptr
	if r, _, _ := procSamConnect.Call(0, uintptr(unsafe.Pointer(&server)), samServerConnect|samServerLookupDomain, uintptr(unsafe.Pointer(&oa))); r != 0 {
		return false, fmt.Errorf("SamConnect : NTSTATUS 0x%08X", r)
	}
	defer procSamCloseHandle.Call(server)
	// Domaine de comptes : celui de la machine, sinon (contrôleur de domaine)
	// le premier domaine SAM qui n'est pas « Builtin ».
	candidates := []string{computer}
	candidates = append(candidates, samDomains(server)...)
	var sid *byte
	var r uintptr
	for _, c := range candidates {
		name, err := windows.NewNTUnicodeString(c)
		if err != nil {
			continue
		}
		if r, _, _ = procSamLookupDomain.Call(server, uintptr(unsafe.Pointer(name)), uintptr(unsafe.Pointer(&sid))); r == 0 && sid != nil {
			break
		}
	}
	if sid == nil {
		return false, fmt.Errorf("SamLookupDomainInSamServer : NTSTATUS 0x%08X", r)
	}
	defer procSamFreeMemory.Call(uintptr(unsafe.Pointer(sid)))
	var dom uintptr
	if r, _, _ := procSamOpenDomain.Call(server, domainReadPwParams, uintptr(unsafe.Pointer(sid)), uintptr(unsafe.Pointer(&dom))); r != 0 {
		return false, fmt.Errorf("SamOpenDomain : NTSTATUS 0x%08X", r)
	}
	defer procSamCloseHandle.Call(dom)
	var info *byte
	if r, _, _ := procSamQueryInfoDomain.Call(dom, domainPasswordInfo, uintptr(unsafe.Pointer(&info))); r != 0 || info == nil {
		return false, fmt.Errorf("SamQueryInformationDomain : NTSTATUS 0x%08X", r)
	}
	defer procSamFreeMemory.Call(uintptr(unsafe.Pointer(info)))
	dpi := (*struct {
		MinLen, History uint16
		Properties      uint32
		MaxAge, MinAge  int64
	})(unsafe.Pointer(info))
	return dpi.Properties&domainPasswordComplex != 0, nil
}

// samDomains énumère les domaines SAM du serveur, hors « Builtin ».
func samDomains(server uintptr) []string {
	if procSamEnumDomains.Find() != nil {
		return nil
	}
	var ctx uint32
	var buf *byte
	var count uint32
	if r, _, _ := procSamEnumDomains.Call(server, uintptr(unsafe.Pointer(&ctx)), uintptr(unsafe.Pointer(&buf)), 0xFFFFFFFF, uintptr(unsafe.Pointer(&count))); r != 0 || buf == nil {
		return nil
	}
	defer procSamFreeMemory.Call(uintptr(unsafe.Pointer(buf)))
	type ridEnum struct {
		RID  uint32
		Name windows.NTUnicodeString
	}
	var out []string
	for _, d := range unsafe.Slice((*ridEnum)(unsafe.Pointer(buf)), count) {
		if n := d.Name.String(); n != "" && !strings.EqualFold(n, "Builtin") {
			out = append(out, n)
		}
	}
	return out
}

func users(dcOnlyBuiltins bool) ([]model.LocalUser, error) {
	var out []model.LocalUser
	var resume uint32
	for {
		var buf *byte
		var read, total uint32
		err := windows.NetUserEnum(nil, 20, filterNormalAccount, &buf, maxPreferredLength, &read, &total, &resume)
		if err != nil && err != windows.Errno(errorMoreData) {
			return nil, fmt.Errorf("NetUserEnum : %w", err)
		}
		type userInfo20 struct {
			Name, FullName, Comment *uint16
			Flags, UserID           uint32
		}
		if buf != nil {
			for _, u := range unsafe.Slice((*userInfo20)(unsafe.Pointer(buf)), read) {
				if dcOnlyBuiltins && u.UserID != 500 && u.UserID != 501 {
					continue
				}
				out = append(out, model.LocalUser{
					Name: windows.UTF16PtrToString(u.Name), RID: u.UserID,
					Enabled:              u.Flags&ufAccountDisable == 0,
					PasswordNotRequired:  u.Flags&ufPasswdNotReqd != 0,
					PasswordNeverExpires: u.Flags&ufDontExpirePasswd != 0,
				})
			}
			windows.NetApiBufferFree(buf)
		}
		if err == nil {
			break
		}
	}
	if out == nil {
		out = []model.LocalUser{}
	}
	return out, nil
}

func admins() ([]model.GroupMember, error) {
	sid, err := windows.StringToSid("S-1-5-32-544")
	if err != nil {
		return nil, err
	}
	group, _, _, err := sid.LookupAccount("")
	if err != nil {
		return nil, err
	}
	g, _ := windows.UTF16PtrFromString(group)
	var out []model.GroupMember
	var resume uintptr
	for {
		var buf *byte
		var read, total uint32
		r, _, _ := procNetLocalGroupGetMembers.Call(0, uintptr(unsafe.Pointer(g)), 2, uintptr(unsafe.Pointer(&buf)),
			maxPreferredLength, uintptr(unsafe.Pointer(&read)), uintptr(unsafe.Pointer(&total)), uintptr(unsafe.Pointer(&resume)))
		if r != 0 && r != errorMoreData {
			return nil, fmt.Errorf("NetLocalGroupGetMembers : %w", windows.Errno(r))
		}
		type membersInfo2 struct {
			SID      *windows.SID
			SIDUsage uint32
			Name     *uint16
		}
		if buf != nil {
			for _, m := range unsafe.Slice((*membersInfo2)(unsafe.Pointer(buf)), read) {
				out = append(out, model.GroupMember{Name: windows.UTF16PtrToString(m.Name), SID: m.SID.String(), Kind: sidUsage(m.SIDUsage)})
			}
			windows.NetApiBufferFree(buf)
		}
		if r == 0 {
			break
		}
	}
	if out == nil {
		out = []model.GroupMember{}
	}
	return out, nil
}

func sidUsage(u uint32) string {
	switch u {
	case windows.SidTypeUser:
		return "user"
	case windows.SidTypeGroup:
		return "group"
	case windows.SidTypeAlias:
		return "alias"
	case windows.SidTypeWellKnownGroup:
		return "well_known"
	case windows.SidTypeDeletedAccount:
		return "deleted"
	}
	return "unknown"
}

func laps() *model.LAPS {
	l := &model.LAPS{}
	for _, k := range []string{
		`HKLM\SOFTWARE\Microsoft\Policies\LAPS`,                      // Intune (CSP)
		`HKLM\SOFTWARE\Policies\Microsoft Windows\LAPS`,              // GPO
		`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\LAPS\Config`, // configuration locale
	} {
		if v := win.ReadValue(k, "BackupDirectory"); v.Exists {
			l.WindowsConfigured, l.BackupDirectory = true, int(v.Uint(0))
			break
		}
	}
	enabled := win.ReadValue(`HKLM\SOFTWARE\Policies\Microsoft Services\AdmPwd`, "AdmPwdEnabled").Uint(0) == 1
	cse := win.KeyExists(`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\GPExtensions\{D76B9641-3288-4f75-942D-087DE603E3EA}`)
	l.Legacy = enabled && cse
	return l
}
