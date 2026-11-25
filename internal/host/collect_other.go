//go:build !windows

package host

import (
	"os"
	"os/user"
	"runtime"

	"github.com/maxb1906/aplomb/internal/model"
)

// Collect, hors Windows, ne renvoie qu'un contexte minimal (développement).
func Collect() model.Host {
	h := model.Host{OS: runtime.GOOS, Arch: runtime.GOARCH, Role: model.RoleWorkstation, JoinType: "unknown", Firmware: "unknown"}
	h.Name, _ = os.Hostname()
	if u, err := user.Current(); err == nil {
		h.User = u.Username
	}
	h.Elevated = os.Geteuid() == 0
	h.Gaps.Set("windows", model.GapAbsent, "not a Windows system")
	return h
}
