// Package collect orchestre la collecte de toutes les sections du snapshot.
package collect

import (
	"errors"
	"fmt"
	"runtime/debug"
	"time"

	"github.com/maxb1906/aplomb/internal/model"
)

// ErrNotWindows : l'audit d'une machine n'est possible que sous Windows.
var ErrNotWindows = errors.New("not windows")

// section est une étape de collecte ; elle remplit sa partie du snapshot.
type section struct {
	name string
	fn   func(s *model.Snapshot)
}

// Progress est appelé au début de chaque section (peut être nil).
type Progress func(section string)

func run(s *model.Snapshot, sections []section, progress Progress) {
	for _, sec := range sections {
		if progress != nil {
			progress(sec.name)
		}
		func() {
			defer func() {
				if r := recover(); r != nil {
					s.Gaps.Set(sec.name, model.GapError, fmt.Sprintf("panic: %v\n%s", r, debug.Stack()))
				}
			}()
			sec.fn(s)
		}()
	}
}

func newSnapshot(version string) *model.Snapshot {
	return &model.Snapshot{Schema: model.SchemaVersion, Tool: "aplomb", Version: version, CollectedAt: time.Now().UTC().Truncate(time.Second)}
}
