package model

// Firewall décrit le pare-feu Windows.
type Firewall struct {
	Profiles []FWProfile `json:"profiles,omitempty"`
	// Rules : règles entrantes actives qui autorisent le trafic.
	Rules []FWRule `json:"rules,omitempty"`
	// OtherFW : pare-feu tiers actifs (Centre de sécurité, postes uniquement).
	OtherFW []string `json:"other_fw,omitempty"`
	Gaps    Gaps     `json:"gaps,omitempty"`
}

// FWProfile est un profil (Domain, Private, Public).
type FWProfile struct {
	Name         string `json:"name"`
	Enabled      bool   `json:"enabled"`
	InboundAllow bool   `json:"inbound_allow"` // action entrante par défaut = Autoriser
	Policy       bool   `json:"policy,omitempty"`
	Active       bool   `json:"active,omitempty"` // profil du réseau actuellement connecté
}

// FWRule est une règle entrante « Autoriser » active.
type FWRule struct {
	Name        string   `json:"name"`
	Grouping    string   `json:"grouping,omitempty"`
	Profiles    []string `json:"profiles"`
	Protocol    int      `json:"protocol"` // 6 TCP, 17 UDP, 256 tous
	LocalPorts  string   `json:"local_ports,omitempty"`
	Remote      string   `json:"remote,omitempty"`
	Application string   `json:"application,omitempty"`
	Service     string   `json:"service,omitempty"`
	App         *PathACL `json:"app,omitempty"` // droits sur le dossier du programme
}

// HasProfile indique si la règle s'applique au profil.
func (r FWRule) HasProfile(p string) bool {
	for _, x := range r.Profiles {
		if x == p {
			return true
		}
	}
	return false
}
