package model

import (
	"encoding/json"
	"fmt"
	"os"
)

// Load lit un snapshot JSON, ou le snapshot contenu dans un rapport JSON
// d'Aplomb (champ "collection").
func Load(path string) (*Snapshot, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var probe struct {
		Collection *Snapshot `json:"collection"`
	}
	if err := json.Unmarshal(data, &probe); err == nil && probe.Collection != nil {
		return probe.Collection, nil
	}
	var s Snapshot
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("%s : %w", path, err)
	}
	if s.Schema == 0 || s.Host.Name == "" {
		return nil, fmt.Errorf("%s : ce n'est pas un snapshot Aplomb", path)
	}
	if s.Schema > SchemaVersion {
		return nil, fmt.Errorf("%s : schéma %d plus récent que celui de cette version (%d)", path, s.Schema, SchemaVersion)
	}
	return &s, nil
}
