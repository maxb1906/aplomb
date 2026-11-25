//go:build !windows

package report

// Open ne fait rien hors Windows (le rapport reste dans le dossier indiqué).
func Open(path string) error { return nil }
