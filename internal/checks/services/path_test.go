package services

import (
	"reflect"
	"testing"
)

const windir = `C:\Windows`

func TestParseImagePath(t *testing.T) {
	cases := []struct {
		raw, exe, args string
		quoted         bool
	}{
		{`"C:\Program Files\App\svc.exe" -k run`, `C:\Program Files\App\svc.exe`, "-k run", true},
		{`C:\Program Files\My App\svc.exe -service`, `C:\Program Files\My App\svc.exe`, "-service", false},
		{`C:\Windows\system32\svchost.exe -k netsvcs -p`, `C:\Windows\system32\svchost.exe`, "-k netsvcs -p", false},
		{`\SystemRoot\System32\svc.exe`, `C:\Windows\System32\svc.exe`, "", false},
		{`system32\drivers\x.sys`, `C:\Windows\system32\drivers\x.sys`, "", false},
		{`\??\C:\Tools\agent.exe`, `C:\Tools\agent.exe`, "", false},
		{`C:\Apps\x.EXE`, `C:\Apps\x.EXE`, "", false},
		{`C:\Apps\daemon.bin /run`, `C:\Apps\daemon.bin`, "/run", false},
		{`"C:\Apps\broken`, `C:\Apps\broken`, "", true},
	}
	for _, c := range cases {
		exe, args, q := ParseImagePath(c.raw, windir)
		if exe != c.exe || args != c.args || q != c.quoted {
			t.Errorf("%q → (%q, %q, %v), attendu (%q, %q, %v)", c.raw, exe, args, q, c.exe, c.args, c.quoted)
		}
	}
}

func TestUnquotedCandidates(t *testing.T) {
	got := UnquotedCandidates(`C:\Program Files\My App\svc.exe`)
	want := []Hijack{
		{Plant: `C:\Program.exe`, Dir: `C:\`},
		{Plant: `C:\Program Files\My.exe`, Dir: `C:\Program Files`},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("%+v", got)
	}
	if len(UnquotedCandidates(`C:\Tools\svc.exe`)) != 0 {
		t.Error("pas d'espace : aucun candidat")
	}
}

func TestUnderAndDir(t *testing.T) {
	if !Under(`C:\WINDOWS\System32\a.exe`, windir) || Under(`C:\WindowsApps\a.exe`, windir) {
		t.Error("Under")
	}
	if Dir(`C:\a.exe`) != `C:\` || Dir(`C:\x\y\a.exe`) != `C:\x\y` {
		t.Error("Dir")
	}
	if !UserWritableLocation(`C:\Users\bob\AppData\Local\x.exe`) || UserWritableLocation(`C:\Program Files\x.exe`) {
		t.Error("UserWritableLocation")
	}
}
