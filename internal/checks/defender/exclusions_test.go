package defender

import "testing"

func TestBroad(t *testing.T) {
	yes := []struct{ k, v string }{
		{"path", `C:\`}, {"path", `D:`}, {"path", `C:\Users`}, {"path", `C:\Users\`}, {"path", `%TEMP%`},
		{"path", `C:\Users\bob\AppData\Local\Temp`}, {"path", `C:\Users\*\Downloads`}, {"path", `C:\Windows`},
		{"extension", "exe"}, {"extension", ".ps1"}, {"extension", "*.dll"}, {"process", "powershell.exe"},
		{"process", `C:\Windows\System32\cmd.exe`}, {"path", "*"},
	}
	for _, c := range yes {
		if !Broad(c.k, c.v) {
			t.Errorf("%s %q devrait être large", c.k, c.v)
		}
	}
	no := []struct{ k, v string }{
		{"path", `C:\Program Files\Veeam\Backup`}, {"path", `D:\SQLData\db.mdf`}, {"extension", "mdf"},
		{"process", `C:\Program Files\App\app.exe`}, {"path", `C:\Windows\SoftwareDistribution\DataStore`},
	}
	for _, c := range no {
		if Broad(c.k, c.v) {
			t.Errorf("%s %q ne devrait pas être large", c.k, c.v)
		}
	}
}

func TestActiveAV(t *testing.T) {
	// 397568 = 0x061100 (actif, à jour), 393472 = 0x060100 (désactivé), 266240 = 0x041000 (actif).
	if !ActiveAV(397568) || ActiveAV(393472) || !ActiveAV(266240) {
		t.Error("ActiveAV")
	}
}
