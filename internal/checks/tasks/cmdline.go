// Package tasks contient les contrôles des tâches planifiées (§ 5.2).
package tasks

import (
	"path"
	"regexp"
	"strings"
)

// SplitArgs découpe une ligne d'arguments en respectant les guillemets.
func SplitArgs(s string) []string {
	var out []string
	var cur strings.Builder
	inQ, has := false, false
	for _, r := range s {
		switch {
		case r == '"':
			inQ, has = !inQ, true
		case (r == ' ' || r == '\t') && !inQ:
			if has {
				out = append(out, cur.String())
				cur.Reset()
				has = false
			}
		default:
			cur.WriteRune(r)
			has = true
		}
	}
	if has {
		out = append(out, cur.String())
	}
	return out
}

// Base renvoie le nom de fichier en minuscules d'un chemin Windows.
func Base(p string) string {
	return strings.ToLower(path.Base(strings.ReplaceAll(p, `\`, "/")))
}

var scriptExt = []string{".ps1", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".py", ".hta"}

// interpreters sont les exécutables qui lancent un script passé en argument.
var interpreters = map[string]bool{
	"powershell.exe": true, "pwsh.exe": true, "cmd.exe": true, "wscript.exe": true, "cscript.exe": true,
	"python.exe": true, "pythonw.exe": true, "mshta.exe": true,
	"powershell": true, "pwsh": true, "cmd": true, "wscript": true, "cscript": true,
}

// ScriptFromArgs renvoie le script lancé par un interpréteur ("" sinon).
func ScriptFromArgs(exe, args string) string {
	if !interpreters[Base(exe)] {
		return ""
	}
	toks := SplitArgs(args)
	for i, t := range toks {
		lt := strings.ToLower(t)
		if (lt == "-file" || lt == "-f") && i+1 < len(toks) {
			return toks[i+1]
		}
	}
	for _, t := range toks {
		lt := strings.ToLower(strings.Trim(t, `'`))
		for _, ext := range scriptExt {
			if strings.HasSuffix(lt, ext) {
				return strings.Trim(t, `'`)
			}
		}
	}
	return ""
}

// ResolveCandidates renvoie les emplacements possibles d'un exécutable donné
// sans chemin complet (« powershell.exe » → System32), dans l'ordre de recherche.
func ResolveCandidates(p, windir string) []string {
	if p == "" {
		return nil
	}
	if strings.Contains(p, `\`) || strings.Contains(p, "/") {
		return []string{p}
	}
	names := []string{p}
	if !strings.Contains(path.Base(p), ".") {
		names = []string{p + ".exe", p}
	}
	var out []string
	for _, n := range names {
		out = append(out, windir+`\System32\`+n, windir+`\`+n, windir+`\System32\WindowsPowerShell\v1.0\`+n)
	}
	return out
}

var (
	reEnc     = regexp.MustCompile(`(^|\s)[-/](e|ec|en|enc|enco|encod|encode|encoded|encodedc|encodedco|encodedcom|encodedcomm|encodedcomma|encodedcomman|encodedcommand)\s`)
	reHidden  = regexp.MustCompile(`(^|\s)[-/]w(i|in|ind|indo|indow|indows|indowst|indowsty|indowstyl|indowstyle)?\s+(h|hi|hid|hidd|hidde|hidden|1)(\s|$)`)
	reURL     = regexp.MustCompile(`(?i)(https?|ftp)://|javascript:|vbscript:`)
	reDownldr = regexp.MustCompile(`(?i)downloadstring|downloadfile|invoke-webrequest|iwr\s|invoke-expression|iex[\s(]|frombase64string|net\.webclient|start-bitstransfer`)
)

// Suspicious renvoie les indices d'une ligne de commande typique de logiciel
// malveillant (vide si rien de suspect).
func Suspicious(exe, args string) []string {
	b := Base(exe)
	la := " " + strings.ToLower(args) + " "
	var out []string
	switch b {
	case "powershell.exe", "pwsh.exe", "powershell", "pwsh":
		if reEnc.MatchString(la) {
			out = append(out, "powershell -EncodedCommand")
		}
		if reHidden.MatchString(la) {
			out = append(out, "powershell -WindowStyle Hidden")
		}
		if reDownldr.MatchString(la) {
			out = append(out, "powershell download/eval")
		}
	case "mshta.exe", "mshta":
		out = append(out, "mshta")
	case "rundll32.exe", "rundll32":
		if reURL.MatchString(la) {
			out = append(out, "rundll32 URL")
		}
	case "certutil.exe", "certutil":
		if strings.Contains(la, "urlcache") || strings.Contains(la, "-decode") || strings.Contains(la, "/decode") {
			out = append(out, "certutil -urlcache/-decode")
		}
	case "bitsadmin.exe", "bitsadmin":
		if strings.Contains(la, "/transfer") || strings.Contains(la, "/addfile") || strings.Contains(la, "/download") {
			out = append(out, "bitsadmin /transfer")
		}
	case "regsvr32.exe", "regsvr32":
		if reURL.MatchString(la) {
			out = append(out, "regsvr32 URL")
		}
	case "cmd.exe", "cmd":
		// cmd /c powershell -enc … : on analyse la commande imbriquée.
		toks := SplitArgs(args)
		for i, t := range toks {
			if bt := Base(t); bt == "powershell.exe" || bt == "powershell" || bt == "pwsh.exe" || bt == "pwsh" || bt == "mshta.exe" || bt == "certutil.exe" || bt == "bitsadmin.exe" {
				return Suspicious(t, strings.Join(toks[i+1:], " "))
			}
		}
	}
	return out
}

// RiskyLocation indique un exécutable placé dans un dossier temporaire,
// de profil utilisateur ou public (writableProgramData : sous ProgramData et
// inscriptible par des non-admins).
func RiskyLocation(p string, writableProgramData bool) bool {
	low := strings.ToLower(p)
	for _, part := range []string{`\temp\`, `\tmp\`, `\appdata\`, `\users\public\`, `\downloads\`} {
		if strings.Contains(low, part) {
			return true
		}
	}
	return writableProgramData && strings.Contains(low, `\programdata\`)
}
