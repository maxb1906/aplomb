package firewall

import (
	"reflect"
	"testing"
)

func TestMatchSensitive(t *testing.T) {
	cases := map[string][]int{
		"3389":           {3389},
		"445, 139":       {139, 445},
		"5000-6000":      {5432, 5900, 5985, 5986},
		"RPC-EPMap":      {135},
		"8080,443":       {},
		"*":              nil,
		"RPC,IPHTTPSIn":  {},
		"1433-1434,3306": {1433, 1434, 3306},
	}
	for in, want := range cases {
		got := MatchSensitive(in)
		if len(want) == 0 && len(got) == 0 {
			continue
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%q → %v, attendu %v", in, got, want)
		}
	}
}

func TestProfiles(t *testing.T) {
	if got := Profiles(0x7FFFFFFF); len(got) != 3 {
		t.Error(got)
	}
	if got := Profiles(6); !reflect.DeepEqual(got, []string{"Private", "Public"}) {
		t.Error(got)
	}
	if !AnyAddress("*") || AnyAddress("LocalSubnet") || !AnyPort("") || AnyPort("80") {
		t.Error("Any*")
	}
}
