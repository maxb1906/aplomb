package system

// setting décrit une valeur de registre lue pour un contrôle : clé de
// stratégie (prioritaire, GPO/Intune) puis clé locale.
type setting struct {
	Policy, Local, Name string
}

const (
	polSystem   = `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`
	polExplorer = `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer`
	polTS       = `HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services`
	lsaKey      = `HKLM\SYSTEM\CurrentControlSet\Control\Lsa`
)

// Settings liste les valeurs collectées, par identifiant.
var Settings = map[string]setting{
	"uac_lua":            {Local: polSystem, Name: "EnableLUA"},
	"uac_consent_admin":  {Local: polSystem, Name: "ConsentPromptBehaviorAdmin"},
	"aie_hklm":           {Policy: `HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer`, Name: "AlwaysInstallElevated"},
	"aie_hkcu":           {Policy: `HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer`, Name: "AlwaysInstallElevated"},
	"rdp_deny":           {Policy: polTS, Local: `HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server`, Name: "fDenyTSConnections"},
	"rdp_nla":            {Policy: polTS, Local: `HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp`, Name: "UserAuthentication"},
	"llmnr":              {Policy: `HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient`, Name: "EnableMulticast"},
	"wdigest":            {Local: `HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest`, Name: "UseLogonCredential"},
	"runasppl":           {Local: lsaKey, Name: "RunAsPPL"},
	"runasppl_boot":      {Local: lsaKey, Name: "RunAsPPLBoot"},
	"lsacfgflags":        {Policy: `HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard`, Local: lsaKey, Name: "LsaCfgFlags"},
	"sbl":                {Policy: `HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging`, Name: "EnableScriptBlockLogging"},
	"nodrivetypeautorun": {Local: polExplorer, Name: "NoDriveTypeAutoRun"},
	"noautorun":          {Local: polExplorer, Name: "NoAutorun"},
	"psv2_engine":        {Local: `HKLM\SOFTWARE\Microsoft\PowerShell\1\PowerShellEngine`, Name: "PowerShellVersion"},
}
