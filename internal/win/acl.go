package win

import (
	"sort"
	"strings"
)

// Kind précise quel usage d'un objet on vérifie.
type Kind int

const (
	KindFile       Kind = iota // remplacer / modifier un fichier
	KindDirCreate              // créer un fichier dans un dossier
	KindDirReplace             // supprimer/remplacer un fichier d'un dossier
	KindKey                    // modifier une clé de registre
)

// Droits d'accès Windows utiles à l'analyse.
const (
	rightWriteData   = 0x2 // FILE_WRITE_DATA / FILE_ADD_FILE / KEY_SET_VALUE
	rightAppend      = 0x4 // FILE_APPEND_DATA / FILE_ADD_SUBDIRECTORY / KEY_CREATE_SUB_KEY
	rightDeleteChild = 0x40
	rightWriteDAC    = 0x40000
	rightWriteOwner  = 0x80000
	rightGenericAll  = 0x10000000
	rightGenericW    = 0x40000000
)

// lowPrivSIDs sont les groupes dont les membres ne sont pas administrateurs.
var lowPrivSIDs = map[string]bool{
	"S-1-1-0":      true, // Tout le monde
	"S-1-5-11":     true, // Utilisateurs authentifiés
	"S-1-5-32-545": true, // Utilisateurs
	"S-1-5-4":      true, // INTERACTIF
	"S-1-5-32-546": true, // Invités
	"S-1-5-7":      true, // ANONYMOUS LOGON
	"S-1-5-2":      true, // RÉSEAU
	"S-1-5-32-547": true, // Utilisateurs avec pouvoir (hérité)
}

// IsLowPrivSID indique un groupe de non-administrateurs (y compris
// « Utilisateurs du domaine » et « Invités du domaine »).
func IsLowPrivSID(sid string) bool {
	if lowPrivSIDs[sid] {
		return true
	}
	return strings.HasPrefix(sid, "S-1-5-21-") && (strings.HasSuffix(sid, "-513") || strings.HasSuffix(sid, "-514"))
}

// DescribeRights renvoie les droits dangereux de mask pour l'usage kind.
func DescribeRights(mask uint32, kind Kind) []string {
	var out []string
	add := func(bit uint32, name string) {
		if mask&bit != 0 {
			out = append(out, name)
		}
	}
	switch kind {
	case KindFile:
		add(rightWriteData, "write")
	case KindDirCreate:
		add(rightWriteData, "add_file")
	case KindDirReplace:
		add(rightDeleteChild, "delete_child")
	case KindKey:
		add(rightWriteData, "set_value")
		add(rightAppend, "create_subkey")
	}
	add(rightWriteDAC, "write_dac")
	add(rightWriteOwner, "write_owner")
	add(rightGenericAll, "generic_all")
	if kind != KindDirReplace {
		add(rightGenericW, "generic_write")
	}
	return out
}

// EffectiveMasks applique les refus aux autorisations, par SID. Un refus à
// « Tout le monde » s'applique à tous les groupes.
func EffectiveMasks(allow, deny map[string]uint32) map[string]uint32 {
	out := map[string]uint32{}
	for sid, m := range allow {
		if e := m &^ deny[sid] &^ deny["S-1-1-0"]; e != 0 {
			out[sid] = e
		}
	}
	return out
}

// SortedSIDs renvoie les clés triées (sortie stable).
func SortedSIDs(m map[string]uint32) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
