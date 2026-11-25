package model

// Services regroupe les services Win32 (hors pilotes).
type Services struct {
	List []Service `json:"list"`
	// Printers : imprimantes installées (hors imprimantes virtuelles Microsoft).
	Printers []string `json:"printers"`
	Gaps     Gaps     `json:"gaps,omitempty"`
}

// Démarrage d'un service (valeur Start du registre).
const (
	StartAuto     = 2
	StartManual   = 3
	StartDisabled = 4
)

// Service décrit un service et les droits des non-admins sur ses éléments.
type Service struct {
	Name        string `json:"name"`
	DisplayName string `json:"display_name,omitempty"`
	ImagePath   string `json:"image_path"`
	Executable  string `json:"executable"`
	Args        string `json:"args,omitempty"`
	Account     string `json:"account"` // vide = LocalSystem
	Start       uint32 `json:"start"`
	Type        uint32 `json:"type"`
	Running     bool   `json:"running"`
	InWindows   bool   `json:"in_windows"` // exécutable sous %SystemRoot%
	Quoted      bool   `json:"quoted"`
	// Hijack : emplacements exploitables d'un chemin non cité contenant des espaces.
	Hijack []HijackDir `json:"hijack,omitempty"`
	Binary *PathACL    `json:"binary,omitempty"`
	Folder *PathACL    `json:"folder,omitempty"` // ajout de fichier dans le dossier
	// FolderReplace : suppression/remplacement de fichiers du dossier.
	FolderReplace *PathACL `json:"folder_replace,omitempty"`
	Key           *PathACL `json:"key,omitempty"`
}

// HijackDir est un emplacement de chemin non cité et les droits sur son dossier.
type HijackDir struct {
	Plant string  `json:"plant"`
	Dir   PathACL `json:"dir"`
}

// LocalSystem indique un service qui tourne sous le compte SYSTEM.
func (s Service) LocalSystem() bool {
	switch s.Account {
	case "", "LocalSystem", `NT AUTHORITY\SYSTEM`, ".\\LocalSystem":
		return true
	}
	return false
}
