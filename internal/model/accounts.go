package model

// Accounts regroupe la politique de mots de passe et les comptes locaux.
type Accounts struct {
	Policy *PasswordPolicy `json:"policy,omitempty"`
	// Users : comptes locaux (sur un DC : seulement Administrateur et Invité).
	Users  []LocalUser   `json:"users,omitempty"`
	Admins []GroupMember `json:"admins,omitempty"` // membres du groupe Administrateurs
	LAPS   *LAPS         `json:"laps,omitempty"`
	Gaps   Gaps          `json:"gaps,omitempty"`
}

// PasswordPolicy est la politique de mots de passe et de verrouillage effective.
type PasswordPolicy struct {
	MinLength          int   `json:"min_length"`
	MaxAgeDays         int   `json:"max_age_days"` // -1 : illimitée
	MinAgeDays         int   `json:"min_age_days"`
	History            int   `json:"history"`
	LockoutThreshold   int   `json:"lockout_threshold"` // 0 : jamais de verrouillage
	LockoutDurationMin int   `json:"lockout_duration_min"`
	LockoutWindowMin   int   `json:"lockout_window_min"`
	Complexity         *bool `json:"complexity,omitempty"`
}

// LocalUser est un compte utilisateur local.
type LocalUser struct {
	Name                 string `json:"name"`
	RID                  uint32 `json:"rid"`
	Enabled              bool   `json:"enabled"`
	PasswordNotRequired  bool   `json:"password_not_required"`
	PasswordNeverExpires bool   `json:"password_never_expires"`
}

// GroupMember est un membre d'un groupe local.
type GroupMember struct {
	Name string `json:"name"`
	SID  string `json:"sid"`
	Kind string `json:"kind"` // user, group, alias, well_known, deleted, unknown
}

// LAPS décrit la gestion des mots de passe administrateur locaux.
type LAPS struct {
	// Windows LAPS : BackupDirectory 0 désactivé, 1 Entra ID, 2 Active Directory.
	WindowsConfigured bool `json:"windows_configured"`
	BackupDirectory   int  `json:"backup_directory"`
	Legacy            bool `json:"legacy"` // ancienne LAPS (AdmPwd) activée et installée
}
