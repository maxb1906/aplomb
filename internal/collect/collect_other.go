//go:build !windows

package collect

import "github.com/maxb1906/aplomb/internal/model"

// Collect n'est disponible que sous Windows ; ailleurs, utiliser
// « aplomb evaluate » sur un snapshot enregistré.
func Collect(version string, progress Progress) (*model.Snapshot, error) {
	return nil, ErrNotWindows
}
