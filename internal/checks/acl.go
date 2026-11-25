// Package checks regroupe les utilitaires communs aux évaluateurs.
package checks

import (
	"strings"

	"github.com/maxb1906/aplomb/internal/model"
)

// Principals résume les droits : « BUILTIN\Utilisateurs (write) ; … ».
func Principals(a *model.PathACL) string {
	if a == nil {
		return ""
	}
	parts := make([]string, 0, len(a.WritableBy))
	for _, p := range a.WritableBy {
		n := p.Name
		if n == "" {
			n = p.SID
		}
		parts = append(parts, n+" ("+p.Rights+")")
	}
	return strings.Join(parts, " ; ")
}

// IcaclsSIDs renvoie les SID au format icacls : « *S-1-5-32-545 *S-1-1-0 ».
func IcaclsSIDs(a *model.PathACL) string {
	parts := make([]string, 0, len(a.WritableBy))
	for _, p := range a.WritableBy {
		parts = append(parts, "*"+p.SID)
	}
	return strings.Join(parts, " ")
}

// PSList renvoie les SID sous forme de liste PowerShell : 'S-1-5-32-545','S-1-1-0'.
func PSList(a *model.PathACL) string {
	parts := make([]string, 0, len(a.WritableBy))
	for _, p := range a.WritableBy {
		parts = append(parts, "'"+p.SID+"'")
	}
	return strings.Join(parts, ",")
}
