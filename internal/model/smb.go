package model

// SMB décrit les partages et la configuration SMB.
type SMB struct {
	Shares []Share `json:"shares,omitempty"`
	// SharesACLHidden : sans admin, les droits des partages ne sont pas lisibles.
	SharesACLHidden bool       `json:"shares_acl_hidden,omitempty"`
	Server          *SMBServer `json:"server,omitempty"`
	Client          *SMBClient `json:"client,omitempty"`
	Gaps            Gaps       `json:"gaps,omitempty"`
}

// Share est un partage de fichiers.
type Share struct {
	Name     string     `json:"name"`
	Path     string     `json:"path,omitempty"`
	Remark   string     `json:"remark,omitempty"`
	Type     uint32     `json:"type"`
	Special  bool       `json:"special"` // partage administratif (C$, ADMIN$, IPC$…)
	ACLKnown bool       `json:"acl_known"`
	Access   []ShareACE `json:"access,omitempty"` // droits de partage des groupes non admins
	// Droits NTFS du dossier partagé pour les mêmes groupes.
	NTFSWrite *PathACL `json:"ntfs_write,omitempty"`
	NTFSRead  *PathACL `json:"ntfs_read,omitempty"`
}

// ShareACE est un droit de partage accordé à un groupe non administrateur.
type ShareACE struct {
	SID   string `json:"sid"`
	Name  string `json:"name,omitempty"`
	Read  bool   `json:"read"`
	Write bool   `json:"write"`
}

// SMBServer est la configuration du serveur SMB (service Serveur).
type SMBServer struct {
	SMB1           *bool  `json:"smb1,omitempty"`
	RequireSigning *bool  `json:"require_signing,omitempty"`
	Source         string `json:"source"` // wmi ou registry
}

// SMBClient est la configuration du client SMB (service Station de travail).
type SMBClient struct {
	SMB1                *bool `json:"smb1,omitempty"`
	InsecureGuest       bool  `json:"insecure_guest"`
	InsecureGuestPolicy bool  `json:"insecure_guest_policy,omitempty"`
}
