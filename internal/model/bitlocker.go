package model

// BitLocker décrit le chiffrement des volumes (admin requis).
type BitLocker struct {
	Volumes []Volume `json:"volumes,omitempty"`
	// BackupPolicy : une stratégie impose la sauvegarde des clés de récupération (AD/Entra).
	BackupPolicy bool `json:"backup_policy"`
	Gaps         Gaps `json:"gaps,omitempty"`
}

// Types de volume (Win32_EncryptableVolume.VolumeType).
const (
	VolumeOS        = 0
	VolumeData      = 1
	VolumeRemovable = 2
)

// Volume est un volume chiffrable.
type Volume struct {
	Mount           string   `json:"mount"`
	DeviceID        string   `json:"device_id,omitempty"`
	Type            int      `json:"type"`
	Protection      int      `json:"protection"` // 0 désactivée, 1 active, 2 inconnue
	Conversion      int      `json:"conversion"` // 0 déchiffré, 1 chiffré, 2 chiffrement en cours, 3 déchiffrement, 4/5 en pause
	Protectors      []string `json:"protectors,omitempty"`
	ProtectorsKnown bool     `json:"protectors_known"`
}

// Encrypted indique un volume chiffré (ou en cours de chiffrement).
func (v Volume) Encrypted() bool { return v.Conversion == 1 || v.Conversion == 2 || v.Conversion == 4 }

// Has indique la présence d'un protecteur.
func (v Volume) Has(p ...string) bool {
	for _, x := range v.Protectors {
		for _, y := range p {
			if x == y {
				return true
			}
		}
	}
	return false
}
