package model

import "time"

// Defender décrit Microsoft Defender Antivirus.
type Defender struct {
	Status *DefenderStatus `json:"status,omitempty"`
	Prefs  *DefenderPrefs  `json:"prefs,omitempty"`
	// OtherAV : antivirus tiers actifs (Centre de sécurité, postes uniquement ; nil = inconnu).
	OtherAV []string `json:"other_av,omitempty"`
	// Policy* : paramètres imposés par stratégie (lisibles sans admin).
	PolicyRealTimeOff bool        `json:"policy_realtime_off,omitempty"`
	PolicyExclusions  []Exclusion `json:"policy_exclusions,omitempty"`
	Gaps              Gaps        `json:"gaps,omitempty"`
}

// DefenderStatus vient de MSFT_MpComputerStatus.
type DefenderStatus struct {
	RunningMode      string     `json:"running_mode,omitempty"` // Normal, Passive Mode, EDR Block Mode…
	AMServiceEnabled bool       `json:"am_service_enabled"`
	AntivirusEnabled bool       `json:"antivirus_enabled"`
	RealTime         bool       `json:"realtime"`
	Tamper           *bool      `json:"tamper,omitempty"`
	SignatureAgeDays int        `json:"signature_age_days"`
	SignatureUpdated *time.Time `json:"signature_updated,omitempty"`
}

// DefenderPrefs vient de MSFT_MpPreference.
type DefenderPrefs struct {
	// ExclusionsVisible : faux sans admin (Defender masque les exclusions).
	ExclusionsVisible bool        `json:"exclusions_visible"`
	Exclusions        []Exclusion `json:"exclusions,omitempty"`
	MAPSReporting     *int        `json:"maps_reporting,omitempty"` // 0 désactivé
	SubmitSamples     *int        `json:"submit_samples,omitempty"` // 2 jamais
	PUA               *int        `json:"pua,omitempty"`            // 0 désactivé, 1 activé, 2 audit
	ASR               []ASRRule   `json:"asr,omitempty"`
}

// Exclusion est une exclusion de l'analyse.
type Exclusion struct {
	Kind   string `json:"kind"` // path, extension, process
	Value  string `json:"value"`
	Policy bool   `json:"policy,omitempty"`
}

// ASRRule est une règle de réduction de la surface d'attaque.
type ASRRule struct {
	ID     string `json:"id"`
	Action int    `json:"action"` // 0 désactivée, 1 bloquer, 2 audit, 6 avertir
}
