package model

// System regroupe les paramètres de durcissement lus dans le registre et
// quelques états d'exécution.
type System struct {
	// Values : valeurs de registre par identifiant (voir checks/system).
	Values map[string]RegValue `json:"values"`
	// NetBIOS : option NetBIOS sur TCP/IP par interface (0 DHCP, 1 activé, 2 désactivé).
	NetBIOS       []NetBIOSIface `json:"netbios,omitempty"`
	NetBTDisabled bool           `json:"netbt_disabled,omitempty"`
	// LSAProtected : lsass.exe tourne en processus protégé (lu si admin).
	LSAProtected *bool `json:"lsa_protected,omitempty"`
	// CredentialGuard : service « Credential Guard » en cours d'exécution (Win32_DeviceGuard).
	CredentialGuard *bool `json:"credential_guard,omitempty"`
	// PSv2 : moteur Windows PowerShell 2.0 installé.
	PSv2 *bool `json:"psv2,omitempty"`
	Gaps Gaps  `json:"gaps,omitempty"`
}

// NetBIOSIface est la configuration NetBIOS d'une interface réseau.
type NetBIOSIface struct {
	ID      string `json:"id"`
	Options int    `json:"options"`
}

// Value renvoie la valeur id (vide si absente).
func (s *System) Value(id string) RegValue {
	if s == nil || s.Values == nil {
		return RegValue{}
	}
	return s.Values[id]
}
