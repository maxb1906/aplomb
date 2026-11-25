// Package smb contient les contrôles des partages et de la configuration SMB (§ 5.2).
package smb

import (
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/maxb1906/aplomb/internal/model"
	"github.com/maxb1906/aplomb/internal/win"
)

var (
	netapi32         = windows.NewLazySystemDLL("netapi32.dll")
	procNetShareEnum = netapi32.NewProc("NetShareEnum")
)

const (
	stypeDisk     = 0
	stypeMask     = 0xFF
	stypeSpecial  = 0x80000000
	errorMoreData = 234
	lanmanServer  = `HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer`
	lanmanWks     = `HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation`
)

// Collect lit les partages, leurs droits et la configuration SMB.
func Collect() *model.SMB {
	out := &model.SMB{}
	shares, err := enum502()
	if err != nil {
		// Sans admin : niveau 1 (nom, type), chemin lu dans le registre.
		shares, err = enum1()
		out.SharesACLHidden = true
	}
	if err != nil {
		out.Gaps.Set("shares", model.GapError, err.Error())
	} else {
		for i := range shares {
			s := &shares[i]
			if s.Special || s.Type&stypeMask != stypeDisk || s.Path == "" {
				continue
			}
			w := win.CheckACL(s.Path, win.KindDirCreate)
			r := win.CheckACL(s.Path, win.KindDirRead)
			s.NTFSWrite, s.NTFSRead = &w, &r
		}
		out.Shares = shares
	}
	out.Server = server()
	out.Client = client()
	return out
}

type shareInfo502 struct {
	Name        *uint16
	Type        uint32
	Remark      *uint16
	Permissions uint32
	MaxUses     uint32
	CurrentUses uint32
	Path        *uint16
	Passwd      *uint16
	Reserved    uint32
	SD          *windows.SECURITY_DESCRIPTOR
}

type shareInfo1 struct {
	Name   *uint16
	Type   uint32
	Remark *uint16
}

func netShareEnum(level uint32, each func(buf *byte, n uint32)) error {
	var resume uint32
	for {
		var buf *byte
		var read, total uint32
		r, _, _ := procNetShareEnum.Call(0, uintptr(level), uintptr(unsafe.Pointer(&buf)), 0xFFFFFFFF,
			uintptr(unsafe.Pointer(&read)), uintptr(unsafe.Pointer(&total)), uintptr(unsafe.Pointer(&resume)))
		if r != 0 && r != errorMoreData {
			return windows.Errno(r)
		}
		if buf != nil {
			each(buf, read)
			windows.NetApiBufferFree(buf)
		}
		if r == 0 {
			return nil
		}
	}
}

func enum502() ([]model.Share, error) {
	var out []model.Share
	err := netShareEnum(502, func(buf *byte, n uint32) {
		for _, si := range unsafe.Slice((*shareInfo502)(unsafe.Pointer(buf)), n) {
			s := model.Share{Name: windows.UTF16PtrToString(si.Name), Remark: windows.UTF16PtrToString(si.Remark),
				Path: windows.UTF16PtrToString(si.Path), Type: si.Type, Special: si.Type&stypeSpecial != 0, ACLKnown: true}
			s.Access = shareAccess(si.SD)
			out = append(out, s)
		}
	})
	if out == nil && err == nil {
		out = []model.Share{}
	}
	return out, err
}

func enum1() ([]model.Share, error) {
	var out []model.Share
	err := netShareEnum(1, func(buf *byte, n uint32) {
		for _, si := range unsafe.Slice((*shareInfo1)(unsafe.Pointer(buf)), n) {
			s := model.Share{Name: windows.UTF16PtrToString(si.Name), Remark: windows.UTF16PtrToString(si.Remark),
				Type: si.Type, Special: si.Type&stypeSpecial != 0}
			s.Path = registryPath(s.Name)
			if sd := registrySD(s.Name); sd != nil {
				s.Access, s.ACLKnown = shareAccess(sd), true
			}
			out = append(out, s)
		}
	})
	if out == nil && err == nil {
		out = []model.Share{}
	}
	return out, err
}

// registryPath lit « Path=… » dans la définition du partage (LanmanServer\Shares).
func registryPath(name string) string {
	v := win.ReadValue(lanmanServer+`\Shares`, name)
	for _, line := range strings.Split(v.Str, "\n") {
		if strings.HasPrefix(strings.ToLower(line), "path=") {
			return line[5:]
		}
	}
	return ""
}

// registrySD lit le descripteur de sécurité d'un partage dans le registre
// (LanmanServer\Shares\Security), quand il est lisible.
func registrySD(name string) *windows.SECURITY_DESCRIPTOR {
	k, err := win.OpenKey(lanmanServer + `\Shares\Security`)
	if err != nil {
		return nil
	}
	defer k.Close()
	data, _, err := k.GetBinaryValue(name)
	if err != nil || len(data) < 20 {
		return nil
	}
	sd := (*windows.SECURITY_DESCRIPTOR)(unsafe.Pointer(&data[0]))
	if !sd.IsValid() {
		return nil
	}
	return sd
}

// shareAccess résume les droits de partage des groupes non administrateurs.
func shareAccess(sd *windows.SECURITY_DESCRIPTOR) []model.ShareACE {
	if sd == nil {
		// Partage sans descripteur : contrôle total pour tout le monde.
		return []model.ShareACE{{SID: "S-1-1-0", Name: win.AccountName("S-1-1-0"), Read: true, Write: true}}
	}
	eff, null := win.LowPrivMasks(sd)
	if null {
		return []model.ShareACE{{SID: "S-1-1-0", Name: win.AccountName("S-1-1-0"), Read: true, Write: true}}
	}
	var out []model.ShareACE
	for _, sid := range win.SortedSIDs(eff) {
		r, w := win.ShareRights(eff[sid])
		if r || w {
			out = append(out, model.ShareACE{SID: sid, Name: win.AccountName(sid), Read: r, Write: w})
		}
	}
	return out
}

func server() *model.SMBServer {
	s := &model.SMBServer{}
	_ = win.WithCOM(func() error {
		return win.WbemQuery(`root\Microsoft\Windows\SMB`, "SELECT EnableSMB1Protocol, RequireSecuritySignature FROM MSFT_SmbServerConfiguration", func(o *win.Disp) error {
			if v, ok := o.Bool("EnableSMB1Protocol"); ok {
				s.SMB1 = &v
			}
			if v, ok := o.Bool("RequireSecuritySignature"); ok {
				s.RequireSigning = &v
			}
			s.Source = "wmi"
			return nil
		})
	})
	if s.Source == "" {
		s.Source = "registry"
		params := lanmanServer + `\Parameters`
		sig := win.ReadValue(params, "RequireSecuritySignature").Uint(0) == 1
		s.RequireSigning = &sig
		smb1 := win.ReadValue(params, "SMB1").Uint(1) != 0 && serviceEnabled("srv")
		s.SMB1 = &smb1
	}
	return s
}

func client() *model.SMBClient {
	c := &model.SMBClient{}
	smb1 := serviceEnabled("mrxsmb10")
	c.SMB1 = &smb1
	v := win.ReadPolicy(`HKLM\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation`, lanmanWks+`\Parameters`, "AllowInsecureGuestAuth")
	c.InsecureGuest, c.InsecureGuestPolicy = v.Uint(0) == 1, v.Policy
	return c
}

// serviceEnabled indique qu'un pilote/service existe et n'est pas désactivé.
func serviceEnabled(name string) bool {
	v := win.ReadValue(`HKLM\SYSTEM\CurrentControlSet\Services\`+name, "Start")
	return v.Exists && v.Uint(4) != 4
}
