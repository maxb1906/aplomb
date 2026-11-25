// Package host collecte le contexte de la machine auditée (§ 5.1).
package host

import (
	"strconv"
	"strings"
	"time"

	"github.com/maxb1906/aplomb/internal/model"
)

// RoleFromProductType traduit la valeur ProductType du registre en rôle.
func RoleFromProductType(pt string) string {
	switch strings.ToLower(pt) {
	case "lanmannt":
		return model.RoleDC
	case "servernt":
		return model.RoleServer
	default:
		return model.RoleWorkstation
	}
}

// FixProductName corrige « Windows 10 » en « Windows 11 » : le registre
// garde ProductName = "Windows 10 …" sur Windows 11 (build ≥ 22000).
func FixProductName(name, build string) string {
	b, err := strconv.Atoi(build)
	if err == nil && b >= 22000 && strings.HasPrefix(name, "Windows 10") {
		return "Windows 11" + strings.TrimPrefix(name, "Windows 10")
	}
	return name
}

// ParseQFEDate lit la date InstalledOn de Win32_QuickFixEngineering :
// « M/D/YYYY » (format habituel, indépendant de la langue), « YYYYMMDD », ou
// un FILETIME en hexadécimal sur de vieux systèmes.
func ParseQFEDate(s string) (time.Time, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, false
	}
	for _, layout := range []string{"1/2/2006", "20060102", "2006-01-02"} {
		if t, err := time.ParseInLocation(layout, s, time.Local); err == nil {
			return t, true
		}
	}
	if len(s) >= 15 {
		if ft, err := strconv.ParseUint(s, 16, 64); err == nil {
			// FILETIME : centaines de ns depuis le 1er janvier 1601.
			const epochDiff = 116444736000000000
			if ft > epochDiff {
				return time.Unix(0, int64(ft-epochDiff)*100), true
			}
		}
	}
	return time.Time{}, false
}

// PortableChassis indique si l'un des types de châssis SMBIOS désigne un
// appareil mobile (portable, tablette, convertible…).
func PortableChassis(types []uint16) bool {
	for _, t := range types {
		switch t {
		case 8, 9, 10, 11, 14, 30, 31, 32:
			return true
		}
	}
	return false
}
