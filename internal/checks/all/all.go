// Package all enregistre tous les contrôles (import pour effet de bord).
package all

import (
	_ "github.com/maxb1906/aplomb/internal/checks/accounts"
	_ "github.com/maxb1906/aplomb/internal/checks/bitlocker"
	_ "github.com/maxb1906/aplomb/internal/checks/defender"
	_ "github.com/maxb1906/aplomb/internal/checks/firewall"
	_ "github.com/maxb1906/aplomb/internal/checks/services"
	_ "github.com/maxb1906/aplomb/internal/checks/smb"
	_ "github.com/maxb1906/aplomb/internal/checks/system"
	_ "github.com/maxb1906/aplomb/internal/checks/tasks"
)
