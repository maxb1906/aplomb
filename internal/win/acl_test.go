package win

import (
	"reflect"
	"testing"
)

func TestIsLowPrivSID(t *testing.T) {
	for sid, want := range map[string]bool{
		"S-1-1-0": true, "S-1-5-32-545": true, "S-1-5-21-1-2-3-513": true,
		"S-1-5-32-544": false, "S-1-5-18": false, "S-1-5-21-1-2-3-512": false, "S-1-5-21-1-2-3-1001": false,
	} {
		if IsLowPrivSID(sid) != want {
			t.Errorf("%s : attendu %v", sid, want)
		}
	}
}

func TestDescribeRights(t *testing.T) {
	// Lecture/exécution seule (0x1200A9) : rien de dangereux.
	if r := DescribeRights(0x1200A9, KindFile); len(r) != 0 {
		t.Errorf("lecture : %v", r)
	}
	// Modification (0x1301BF) sur un fichier : écriture.
	if r := DescribeRights(0x1301BF, KindFile); !reflect.DeepEqual(r, []string{"write"}) {
		t.Errorf("modify : %v", r)
	}
	// Contrôle total sur un dossier : remplacement possible.
	if r := DescribeRights(0x1F01FF, KindDirReplace); !reflect.DeepEqual(r, []string{"delete_child", "write_dac", "write_owner"}) {
		t.Errorf("full dir : %v", r)
	}
	// Ajout de sous-dossier seulement (0x4) : pas de création de fichier.
	if r := DescribeRights(0x4|0x1200A9, KindDirCreate); len(r) != 0 {
		t.Errorf("add subdir : %v", r)
	}
	if r := DescribeRights(0x6, KindKey); !reflect.DeepEqual(r, []string{"set_value", "create_subkey"}) {
		t.Errorf("clé : %v", r)
	}
}

func TestEffectiveMasks(t *testing.T) {
	allow := map[string]uint32{"S-1-5-32-545": 0x6, "S-1-5-11": 0x2}
	deny := map[string]uint32{"S-1-5-32-545": 0x2, "S-1-1-0": 0x4}
	got := EffectiveMasks(allow, deny)
	if len(got) != 1 || got["S-1-5-11"] != 0x2 {
		t.Errorf("%v", got)
	}
}
