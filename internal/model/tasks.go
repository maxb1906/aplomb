package model

// Tasks regroupe les tâches planifiées.
type Tasks struct {
	List []Task `json:"list"`
	// Partial : sans droits admin, les tâches des autres comptes ne sont pas visibles.
	Partial bool `json:"partial"`
	// Unreadable : tâches énumérées mais dont la définition est illisible.
	Unreadable int  `json:"unreadable,omitempty"`
	Gaps       Gaps `json:"gaps,omitempty"`
}

// Task est une tâche planifiée.
type Task struct {
	Path         string       `json:"path"`   // \Dossier\Nom
	Folder       string       `json:"folder"` // \Dossier\ (avec la barre finale)
	Name         string       `json:"name"`
	Enabled      bool         `json:"enabled"`
	Hidden       bool         `json:"hidden"`
	Author       string       `json:"author,omitempty"`
	UserID       string       `json:"user_id,omitempty"`
	PrincipalSID string       `json:"principal_sid,omitempty"`
	GroupID      string       `json:"group_id,omitempty"`
	RunLevel     int          `json:"run_level"` // 1 = privilèges les plus élevés
	Privileged   bool         `json:"privileged"`
	Actions      []TaskAction `json:"actions"`
}

// TaskAction est une action « lancer un programme » d'une tâche.
type TaskAction struct {
	Path     string `json:"path"`
	Args     string `json:"args,omitempty"`
	WorkDir  string `json:"work_dir,omitempty"`
	Resolved string `json:"resolved"` // chemin complet après résolution
	Exists   bool   `json:"exists"`
	// File : droits sur l'exécutable ; Replace : remplacement dans son dossier ;
	// Create : création dans le dossier (exécutable manquant).
	File    *PathACL `json:"file,omitempty"`
	Replace *PathACL `json:"replace,omitempty"`
	Create  *PathACL `json:"create,omitempty"`
	// Script lancé par un interpréteur (powershell -File x.ps1…).
	Script        string   `json:"script,omitempty"`
	ScriptExists  bool     `json:"script_exists,omitempty"`
	ScriptFile    *PathACL `json:"script_file,omitempty"`
	ScriptReplace *PathACL `json:"script_replace,omitempty"`
}
