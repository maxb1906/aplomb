package collect

import (
	"time"

	"github.com/maxb1906/aplomb/internal/host"
	"github.com/maxb1906/aplomb/internal/model"
)

// sections liste les collecteurs, dans l'ordre d'exécution.
var sections = []section{
	{"host", func(s *model.Snapshot) { s.Host = host.Collect() }},
}

// Collect lit la configuration de la machine (lecture seule).
func Collect(version string, progress Progress) (*model.Snapshot, error) {
	start := time.Now()
	s := newSnapshot(version)
	run(s, sections, progress)
	s.DurationMS = time.Since(start).Milliseconds()
	return s, nil
}
