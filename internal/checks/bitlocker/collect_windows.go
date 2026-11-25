// Package bitlocker contient les contrôles du chiffrement BitLocker (§ 5.2).
package bitlocker

import (
	"strconv"

	"github.com/maxb1906/aplomb/internal/model"
	"github.com/maxb1906/aplomb/internal/win"
)

const namespace = `root\CIMV2\Security\MicrosoftVolumeEncryption`

var protectorNames = map[int64]string{
	1: "tpm", 2: "external_key", 3: "recovery_password", 4: "tpm_pin", 5: "tpm_key",
	6: "tpm_pin_key", 7: "public_key", 8: "passphrase", 9: "tpm_certificate", 10: "sid",
}

// Collect lit Win32_EncryptableVolume (droits admin requis).
func Collect() *model.BitLocker {
	out := &model.BitLocker{}
	fve := `HKLM\SOFTWARE\Policies\Microsoft\FVE`
	out.BackupPolicy = win.ReadValue(fve, "OSRequireActiveDirectoryBackup").Uint(0) == 1 ||
		win.ReadValue(fve, "OSActiveDirectoryBackup").Uint(0) == 1
	vols := []model.Volume{}
	err := win.WithCOM(func() error {
		return win.WbemQuery(namespace, "SELECT * FROM Win32_EncryptableVolume", func(o *win.Disp) error {
			v := model.Volume{Mount: o.Str("DriveLetter"), DeviceID: o.Str("DeviceID")}
			if v.Mount == "" {
				v.Mount = v.DeviceID
			}
			t, _ := o.Int("VolumeType")
			p, _ := o.Int("ProtectionStatus")
			c, _ := o.Int("ConversionStatus")
			v.Type, v.Protection, v.Conversion = int(t), int(p), int(c)
			v.Protectors, v.ProtectorsKnown = protectors(o)
			vols = append(vols, v)
			return nil
		})
	})
	switch {
	case err == nil:
		out.Volumes = vols
	case win.IsNotFound(err):
		out.Gaps.Set("volumes", model.GapAbsent, err.Error())
	case win.IsAccessDenied(err):
		out.Gaps.Set("volumes", model.GapAdmin, err.Error())
	default:
		out.Gaps.Set("volumes", model.GapError, err.Error())
	}
	return out
}

func protectors(o *win.Disp) ([]string, bool) {
	res, err := o.ExecMethod("GetKeyProtectors", map[string]any{"KeyProtectorType": 0})
	if err != nil {
		return nil, false
	}
	defer res.Release()
	ids, ok := res.Strings("VolumeKeyProtectorID")
	if !ok {
		return nil, false
	}
	var out []string
	for _, id := range ids {
		r, err := o.ExecMethod("GetKeyProtectorType", map[string]any{"VolumeKeyProtectorID": id})
		if err != nil {
			return out, false
		}
		t, _ := r.Int("KeyProtectorType")
		r.Release()
		if n, ok := protectorNames[t]; ok {
			out = append(out, n)
		} else {
			out = append(out, "type_"+strconv.FormatInt(t, 10))
		}
	}
	return out, true
}
