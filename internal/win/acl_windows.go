package win

import (
	"errors"
	"strings"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/maxb1906/aplomb/internal/model"
)

var (
	aclMu    sync.Mutex
	aclCache = map[string]model.PathACL{}
	nameMu   sync.Mutex
	names    = map[string]string{}
)

// AccountName renvoie « DOMAINE\nom » pour un SID (nom localisé), ou le SID.
func AccountName(sidStr string) string {
	nameMu.Lock()
	defer nameMu.Unlock()
	if n, ok := names[sidStr]; ok {
		return n
	}
	n := sidStr
	if sid, err := windows.StringToSid(sidStr); err == nil {
		if acc, dom, _, err := sid.LookupAccount(""); err == nil {
			n = acc
			if dom != "" {
				n = dom + `\` + acc
			}
		}
	}
	names[sidStr] = n
	return n
}

// regObjectName convertit « HKLM\X » au format attendu par GetNamedSecurityInfo.
func regObjectName(p string) string {
	root, rest, _ := strings.Cut(p, `\`)
	switch strings.ToUpper(root) {
	case "HKLM", "HKEY_LOCAL_MACHINE":
		return `MACHINE\` + rest
	case "HKU", "HKEY_USERS":
		return `USERS\` + rest
	case "HKCU", "HKEY_CURRENT_USER":
		return `CURRENT_USER\` + rest
	}
	return p
}

// CheckACL indique quels groupes non administrateurs peuvent modifier path.
// Les résultats sont mis en cache (de nombreux services partagent un binaire).
func CheckACL(path string, kind Kind) model.PathACL {
	key := strings.ToLower(path) + "|" + string(rune('0'+kind))
	aclMu.Lock()
	if r, ok := aclCache[key]; ok {
		aclMu.Unlock()
		return r
	}
	aclMu.Unlock()
	r := checkACL(path, kind)
	aclMu.Lock()
	aclCache[key] = r
	aclMu.Unlock()
	return r
}

func checkACL(path string, kind Kind) model.PathACL {
	res := model.PathACL{Path: path}
	var objType windows.SE_OBJECT_TYPE = windows.SE_FILE_OBJECT
	name := path
	if kind == KindKey {
		objType, name = windows.SE_REGISTRY_KEY, regObjectName(path)
	}
	sd, err := windows.GetNamedSecurityInfo(name, objType, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		if errors.Is(err, windows.ERROR_FILE_NOT_FOUND) || errors.Is(err, windows.ERROR_PATH_NOT_FOUND) || errors.Is(err, windows.ERROR_INVALID_NAME) {
			return res
		}
		res.Exists = true
		res.Error = err.Error()
		return res
	}
	res.Exists = true
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil {
		// Pas de DACL : accès total pour tout le monde.
		res.WritableBy = []model.Principal{{SID: "S-1-1-0", Name: AccountName("S-1-1-0"), Rights: "null_dacl"}}
		return res
	}
	allow, deny := map[string]uint32{}, map[string]uint32{}
	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			continue
		}
		if ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0 {
			continue
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart)).String()
		if !IsLowPrivSID(sid) {
			continue
		}
		switch ace.Header.AceType {
		case windows.ACCESS_ALLOWED_ACE_TYPE:
			allow[sid] |= uint32(ace.Mask)
		case windows.ACCESS_DENIED_ACE_TYPE:
			deny[sid] |= uint32(ace.Mask)
		}
	}
	eff := EffectiveMasks(allow, deny)
	for _, sid := range SortedSIDs(eff) {
		if rights := DescribeRights(eff[sid], kind); len(rights) > 0 {
			res.WritableBy = append(res.WritableBy, model.Principal{SID: sid, Name: AccountName(sid), Rights: strings.Join(rights, ",")})
		}
	}
	return res
}
