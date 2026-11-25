// Package services contient les contrôles des services Windows (§ 5.2).
package services

import (
	"path"
	"strings"
)

// winPath manipule des chemins Windows quel que soit l'OS de compilation
// (tests sur la devbox) : on travaille avec des « / » puis on reconvertit.
func toSlash(p string) string   { return strings.ReplaceAll(p, `\`, "/") }
func fromSlash(p string) string { return strings.ReplaceAll(p, "/", `\`) }

// Dir renvoie le dossier parent d'un chemin Windows.
func Dir(p string) string {
	d := fromSlash(path.Dir(toSlash(p)))
	if len(d) == 2 && d[1] == ':' {
		d += `\`
	}
	return d
}

// Under indique si p est dans le dossier dir (comparaison insensible à la casse).
func Under(p, dir string) bool {
	if dir == "" {
		return false
	}
	p, dir = strings.ToLower(p), strings.ToLower(strings.TrimRight(dir, `\`))+`\`
	return strings.HasPrefix(p, dir)
}

// ParseImagePath sépare l'exécutable et les arguments d'une ligne de commande
// de service. windir sert à résoudre « \SystemRoot\ » et « system32\… ».
func ParseImagePath(raw, windir string) (exe, args string, quoted bool) {
	s := strings.TrimSpace(raw)
	s = strings.TrimPrefix(s, `\??\`)
	if strings.HasPrefix(s, `"`) {
		end := strings.Index(s[1:], `"`)
		if end < 0 {
			return resolve(s[1:], windir), "", true
		}
		return resolve(s[1:end+1], windir), strings.TrimSpace(s[end+2:]), true
	}
	low := strings.ToLower(s)
	for i := 0; i+4 <= len(low); i++ {
		if low[i:i+4] == ".exe" && (i+4 == len(low) || low[i+4] == ' ') {
			return resolve(s[:i+4], windir), strings.TrimSpace(s[i+4:]), false
		}
	}
	// Sans « .exe » : l'exécutable s'arrête au premier argument (-x ou /x).
	for _, sep := range []string{" -", " /"} {
		if i := strings.Index(s, sep); i > 0 {
			return resolve(s[:i], windir), strings.TrimSpace(s[i:]), false
		}
	}
	return resolve(s, windir), "", false
}

func resolve(p, windir string) string {
	low := strings.ToLower(p)
	switch {
	case strings.HasPrefix(low, `\systemroot\`):
		return windir + p[len(`\systemroot`):]
	case strings.HasPrefix(low, `system32\`), strings.HasPrefix(low, `syswow64\`):
		return strings.TrimRight(windir, `\`) + `\` + p
	}
	return p
}

// Hijack est un emplacement où Windows chercherait un exécutable à cause d'un
// chemin sans guillemets : « C:\Program Files\A B\x.exe » → « C:\Program.exe ».
type Hijack struct {
	Plant string // fichier qu'un attaquant devrait créer
	Dir   string // dossier où il faudrait pouvoir écrire
}

// UnquotedCandidates renvoie les emplacements exploitables d'un chemin non cité.
func UnquotedCandidates(exe string) []Hijack {
	var out []Hijack
	for i := 0; i < len(exe); i++ {
		if exe[i] != ' ' {
			continue
		}
		prefix := exe[:i]
		if strings.HasSuffix(prefix, `\`) || prefix == "" {
			continue
		}
		out = append(out, Hijack{Plant: prefix + ".exe", Dir: Dir(prefix)})
	}
	return out
}

// UserWritableLocation indique un chemin dans un dossier utilisateur ou temporaire.
func UserWritableLocation(p string) bool {
	low := strings.ToLower(p)
	for _, part := range []string{`\users\`, `\appdata\`, `\temp\`, `\tmp\`, `\downloads\`, `\téléchargements\`} {
		if strings.Contains(low, part) {
			return true
		}
	}
	return false
}
