package host

import (
	"testing"
	"time"
)

func TestRoleFromProductType(t *testing.T) {
	for in, want := range map[string]string{"WinNT": "workstation", "ServerNT": "server", "LanmanNT": "dc", "": "workstation"} {
		if got := RoleFromProductType(in); got != want {
			t.Errorf("%q → %q, attendu %q", in, got, want)
		}
	}
}

func TestFixProductName(t *testing.T) {
	if got := FixProductName("Windows 10 Pro", "22631"); got != "Windows 11 Pro" {
		t.Error(got)
	}
	if got := FixProductName("Windows 10 Pro", "19045"); got != "Windows 10 Pro" {
		t.Error(got)
	}
	if got := FixProductName("Windows Server 2022 Standard", "20348"); got != "Windows Server 2022 Standard" {
		t.Error(got)
	}
}

func TestParseQFEDate(t *testing.T) {
	d, ok := ParseQFEDate("11/3/2026")
	if !ok || d.Year() != 2026 || d.Month() != time.November || d.Day() != 3 {
		t.Errorf("M/D/YYYY : %v %v", d, ok)
	}
	if _, ok := ParseQFEDate("20261103"); !ok {
		t.Error("YYYYMMDD")
	}
	if d, ok := ParseQFEDate("01d2b3c4e5f60000"); !ok || d.Year() < 2016 {
		t.Errorf("FILETIME hex : %v %v", d, ok)
	}
	if _, ok := ParseQFEDate(""); ok {
		t.Error("vide")
	}
}

func TestPortableChassis(t *testing.T) {
	if !PortableChassis([]uint16{3, 10}) || PortableChassis([]uint16{3}) || PortableChassis(nil) {
		t.Error("PortableChassis")
	}
}
