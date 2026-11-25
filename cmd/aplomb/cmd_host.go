package main

import (
	"encoding/json"

	"github.com/maxb1906/aplomb/internal/host"
)

// cmdHost affiche le contexte de la machine en JSON.
func cmdHost(e *env, _ []string) int {
	enc := json.NewEncoder(e.stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(host.Collect()); err != nil {
		return e.fail(err)
	}
	return 0
}
