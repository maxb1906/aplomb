// Package model décrit les données brutes collectées sur la machine auditée
// (« snapshot »). Il ne contient aucune logique Windows : un snapshot peut être
// enregistré en JSON puis réévalué n'importe où, ce qui permet de tester les
// règles sur la devbox à partir de fixtures.
package model

import "time"

// SchemaVersion est la version du format JSON du snapshot.
const SchemaVersion = 1

// Rôles de la machine, utilisés par les profils des règles.
const (
	RoleWorkstation = "workstation"
	RoleServer      = "server"
	RoleDC          = "dc"
)

// Raisons d'une donnée manquante.
const (
	GapAdmin  = "requires_admin" // relancer en administrateur
	GapError  = "error"          // erreur de collecte
	GapAbsent = "absent"         // fonctionnalité absente sur cette machine
)

// Gap explique pourquoi une donnée n'a pas pu être collectée.
type Gap struct {
	Reason string `json:"reason"`
	Detail string `json:"detail,omitempty"`
}

// Gaps associe un composant (ex. "policy", "users") à la raison de son absence.
type Gaps map[string]Gap

// Set enregistre une donnée manquante.
func (g *Gaps) Set(component, reason, detail string) {
	if *g == nil {
		*g = Gaps{}
	}
	(*g)[component] = Gap{Reason: reason, Detail: detail}
}

// Get renvoie la raison de l'absence de component (GapError par défaut).
func (g Gaps) Get(component string) Gap {
	if gap, ok := g[component]; ok {
		return gap
	}
	return Gap{Reason: GapError, Detail: "no data"}
}

// Snapshot regroupe toutes les données collectées lors d'un audit.
type Snapshot struct {
	Schema      int        `json:"schema"`
	Tool        string     `json:"tool"`
	Version     string     `json:"version"`
	CollectedAt time.Time  `json:"collected_at"`
	DurationMS  int64      `json:"duration_ms"`
	Host        Host       `json:"host"`
	Services    *Services  `json:"services,omitempty"`
	Tasks       *Tasks     `json:"tasks,omitempty"`
	Accounts    *Accounts  `json:"accounts,omitempty"`
	BitLocker   *BitLocker `json:"bitlocker,omitempty"`
	Defender    *Defender  `json:"defender,omitempty"`
	// Gaps liste les sections entières non collectées (clé : nom de section).
	Gaps Gaps `json:"gaps,omitempty"`
}

// Host décrit le contexte de la machine (§ 5.1).
type Host struct {
	Name             string     `json:"name"`
	OS               string     `json:"os"`
	Edition          string     `json:"edition,omitempty"`
	DisplayVersion   string     `json:"display_version,omitempty"`
	Build            string     `json:"build,omitempty"`
	UBR              uint64     `json:"ubr,omitempty"`
	InstallationType string     `json:"installation_type,omitempty"` // Client, Server, Server Core
	ProductType      string     `json:"product_type,omitempty"`      // WinNT, ServerNT, LanmanNT
	Role             string     `json:"role"`
	Arch             string     `json:"arch"`
	JoinType         string     `json:"join_type"` // workgroup, domain, unknown
	Domain           string     `json:"domain,omitempty"`
	ComputerDN       string     `json:"computer_dn,omitempty"`
	EntraJoined      bool       `json:"entra_joined"`
	EntraTenant      string     `json:"entra_tenant,omitempty"`
	User             string     `json:"user"`
	Elevated         bool       `json:"elevated"`
	Firmware         string     `json:"firmware"` // uefi, bios, unknown
	SecureBoot       *bool      `json:"secure_boot,omitempty"`
	TPMPresent       *bool      `json:"tpm_present,omitempty"`
	TPMVersion       string     `json:"tpm_version,omitempty"`
	Portable         *bool      `json:"portable,omitempty"`
	LastUpdate       *time.Time `json:"last_update,omitempty"`
	LastUpdateKB     string     `json:"last_update_kb,omitempty"`
	Gaps             Gaps       `json:"gaps,omitempty"`
}

// Joined indique une appartenance à un domaine AD ou à Entra ID.
func (h Host) Joined() bool { return h.JoinType == "domain" || h.EntraJoined }

// Principal est un compte ou groupe qui détient des droits sur un objet.
type Principal struct {
	SID    string `json:"sid"`
	Name   string `json:"name,omitempty"`
	Rights string `json:"rights,omitempty"` // ex. "write,write_dac"
}

// PathACL résume les droits d'écriture des non-administrateurs sur un fichier,
// un dossier ou une clé de registre.
type PathACL struct {
	Path       string      `json:"path"`
	Exists     bool        `json:"exists"`
	WritableBy []Principal `json:"writable_by,omitempty"`
	Error      string      `json:"error,omitempty"`
}

// Writable indique qu'au moins un principal non administrateur peut modifier l'objet.
func (p *PathACL) Writable() bool { return p != nil && len(p.WritableBy) > 0 }

// RegValue est une valeur de registre lue pour un contrôle.
type RegValue struct {
	Path   string  `json:"path"`
	Name   string  `json:"name"`
	Exists bool    `json:"exists"`
	Num    *uint64 `json:"num,omitempty"`
	Str    string  `json:"str,omitempty"`
	// Policy : la valeur vient d'une clé de stratégie (GPO, Intune).
	Policy bool `json:"policy,omitempty"`
}

// Uint renvoie la valeur numérique, ou def si elle est absente.
func (r RegValue) Uint(def uint64) uint64 {
	if !r.Exists || r.Num == nil {
		return def
	}
	return *r.Num
}

// Bool, Ptr et Int sont des petits utilitaires pour les champs optionnels.
func Bool(b bool) *bool    { return &b }
func Int(i int) *int       { return &i }
func U64(u uint64) *uint64 { return &u }
