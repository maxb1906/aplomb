// Package defender contient les contrôles de Microsoft Defender (§ 5.2).
package defender

import (
	"regexp"
	"strings"
)

var (
	reDriveRoot = regexp.MustCompile(`^[a-z]:\\?\*?$`)
	broadDirs   = []string{
		`c:\users`, `c:\users\*`, `c:\windows`, `c:\windows\temp`, `c:\programdata`, `c:\program files`, `c:\program files (x86)`,
		`%temp%`, `%tmp%`, `%appdata%`, `%localappdata%`, `%userprofile%`, `%systemroot%`, `%windir%`, `%programdata%`, `%public%`,
		`c:\users\public`,
	}
	broadParts = []string{`\appdata\local\temp`, `\appdata\roaming`, `\appdata\local`, `\downloads`, `\temp`, `\desktop`}
	broadExt   = map[string]bool{
		"exe": true, "dll": true, "ps1": true, "bat": true, "cmd": true, "vbs": true, "js": true, "scr": true,
		"com": true, "msi": true, "hta": true, "jar": true, "lnk": true, "zip": true, "*": true, "": true,
	}
	broadProc = map[string]bool{
		"powershell.exe": true, "pwsh.exe": true, "cmd.exe": true, "wscript.exe": true, "cscript.exe": true,
		"mshta.exe": true, "rundll32.exe": true, "regsvr32.exe": true, "msiexec.exe": true, "explorer.exe": true,
		"svchost.exe": true, "*": true,
	}
)

// Broad indique une exclusion assez large pour neutraliser l'antivirus
// (lecteur entier, profils, dossiers temporaires, extensions exécutables…).
func Broad(kind, value string) bool {
	v := strings.ToLower(strings.TrimSpace(value))
	switch kind {
	case "extension":
		return broadExt[strings.TrimLeft(v, "*.")]
	case "process":
		base := v
		if i := strings.LastIndexAny(v, `\/`); i >= 0 {
			base = v[i+1:]
		}
		return broadProc[base]
	}
	v = strings.TrimRight(v, `\`)
	if v == "*" || reDriveRoot.MatchString(v) || reDriveRoot.MatchString(v+`\`) {
		return true
	}
	for _, d := range broadDirs {
		if v == d || v == d+`\*` {
			return true
		}
	}
	for _, p := range broadParts {
		if strings.HasSuffix(v, p) || strings.HasSuffix(v, p+`\*`) || strings.Contains(v, p+`\*`) {
			return true
		}
	}
	return false
}

// HiddenByDefender reconnaît la valeur renvoyée sans droits admin.
func HiddenByDefender(v string) bool {
	return strings.HasPrefix(strings.TrimSpace(v), "N/A")
}

// ActiveAV décode productState (Centre de sécurité) : l'antivirus est actif
// quand l'octet d'état vaut 0x10 (0x1000 dans la valeur).
func ActiveAV(productState int64) bool {
	return (productState>>8)&0xF0 == 0x10
}
