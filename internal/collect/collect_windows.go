package collect

import (
	"time"

	"github.com/maxb1906/aplomb/internal/checks/accounts"
	"github.com/maxb1906/aplomb/internal/checks/bitlocker"
	"github.com/maxb1906/aplomb/internal/checks/defender"
	"github.com/maxb1906/aplomb/internal/checks/firewall"
	"github.com/maxb1906/aplomb/internal/checks/services"
	"github.com/maxb1906/aplomb/internal/checks/smb"
	"github.com/maxb1906/aplomb/internal/checks/system"
	"github.com/maxb1906/aplomb/internal/checks/tasks"
	"github.com/maxb1906/aplomb/internal/host"
	"github.com/maxb1906/aplomb/internal/model"
)

// sections liste les collecteurs, dans l'ordre d'exécution.
var sections = []section{
	{"host", func(s *model.Snapshot) { s.Host = host.Collect() }},
	{"services", func(s *model.Snapshot) { s.Services = services.Collect() }},
	{"tasks", func(s *model.Snapshot) { s.Tasks = tasks.Collect(s.Host.Elevated) }},
	{"accounts", func(s *model.Snapshot) { s.Accounts = accounts.Collect(s.Host) }},
	{"bitlocker", func(s *model.Snapshot) { s.BitLocker = bitlocker.Collect() }},
	{"defender", func(s *model.Snapshot) { s.Defender = defender.Collect(s.Host) }},
	{"smb", func(s *model.Snapshot) { s.SMB = smb.Collect() }},
	{"firewall", func(s *model.Snapshot) { s.Firewall = firewall.Collect(s.Host) }},
	{"system", func(s *model.Snapshot) { s.System = system.Collect(s.Host) }},
}

// Collect lit la configuration de la machine (lecture seule).
func Collect(version string, progress Progress) (*model.Snapshot, error) {
	start := time.Now()
	s := newSnapshot(version)
	run(s, sections, progress)
	s.DurationMS = time.Since(start).Milliseconds()
	return s, nil
}
