// Package win regroupe les accès bas niveau à Windows (registre, WMI, COM,
// ACL) utilisés par les collecteurs. Tout y est en lecture seule.
package win

import (
	"errors"
	"strings"

	"golang.org/x/sys/windows/registry"

	"github.com/maxb1906/aplomb/internal/model"
)

// splitRoot sépare "HKLM\SOFTWARE\..." en racine et chemin.
func splitRoot(full string) (registry.Key, string) {
	root, rest, _ := strings.Cut(full, `\`)
	switch strings.ToUpper(root) {
	case "HKCU", "HKEY_CURRENT_USER":
		return registry.CURRENT_USER, rest
	case "HKU", "HKEY_USERS":
		return registry.USERS, rest
	default:
		return registry.LOCAL_MACHINE, rest
	}
}

// OpenKey ouvre une clé en lecture (vue 64 bits).
func OpenKey(full string) (registry.Key, error) {
	root, path := splitRoot(full)
	return registry.OpenKey(root, path, registry.QUERY_VALUE|registry.ENUMERATE_SUB_KEYS|registry.WOW64_64KEY)
}

// KeyExists indique si la clé existe (et est lisible).
func KeyExists(full string) bool {
	k, err := OpenKey(full)
	if err != nil {
		return false
	}
	k.Close()
	return true
}

// SubKeys renvoie les noms des sous-clés.
func SubKeys(full string) ([]string, error) {
	k, err := OpenKey(full)
	if err != nil {
		return nil, err
	}
	defer k.Close()
	return k.ReadSubKeyNames(-1)
}

// ReadValue lit une valeur, numérique ou texte.
func ReadValue(full, name string) model.RegValue {
	v := model.RegValue{Path: full, Name: name}
	k, err := OpenKey(full)
	if err != nil {
		return v
	}
	defer k.Close()
	if n, _, err := k.GetIntegerValue(name); err == nil {
		v.Exists, v.Num = true, model.U64(n)
		return v
	} else if !errors.Is(err, registry.ErrUnexpectedType) {
		return v
	}
	if s, _, err := k.GetStringValue(name); err == nil {
		v.Exists, v.Str = true, s
		return v
	}
	if ss, _, err := k.GetStringsValue(name); err == nil {
		v.Exists, v.Str = true, strings.Join(ss, "\n")
	}
	return v
}

// ReadString lit une valeur texte ("" si absente).
func ReadString(full, name string) string {
	return ReadValue(full, name).Str
}

// ReadPolicy lit d'abord la valeur imposée par stratégie (policyPath), puis la
// valeur locale (localPath). Policy est vrai si la stratégie l'emporte.
func ReadPolicy(policyPath, localPath, name string) model.RegValue {
	if policyPath != "" {
		if v := ReadValue(policyPath, name); v.Exists {
			v.Policy = true
			return v
		}
	}
	if localPath == "" {
		return model.RegValue{Path: policyPath, Name: name}
	}
	return ReadValue(localPath, name)
}

// ExpandEnv développe les variables %VAR% d'une chaîne.
func ExpandEnv(s string) string {
	if !strings.Contains(s, "%") {
		return s
	}
	out, err := registry.ExpandString(s)
	if err != nil {
		return s
	}
	return out
}
