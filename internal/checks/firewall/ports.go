// Package firewall contient les contrôles du pare-feu Windows (§ 5.2).
package firewall

import (
	"sort"
	"strconv"
	"strings"
)

// SensitivePorts sont les services à ne jamais exposer à toute adresse sur un
// réseau public.
var SensitivePorts = map[int]string{
	21: "FTP", 22: "SSH", 23: "Telnet", 135: "RPC", 139: "NetBIOS", 445: "SMB", 1433: "SQL Server", 1434: "SQL Browser",
	1521: "Oracle", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC", 5985: "WinRM", 5986: "WinRM HTTPS",
	6379: "Redis", 9200: "Elasticsearch", 27017: "MongoDB",
}

// AnyPort indique une règle sans restriction de port.
func AnyPort(localPorts string) bool {
	p := strings.TrimSpace(localPorts)
	return p == "" || p == "*"
}

// AnyAddress indique une règle sans restriction d'adresse distante.
func AnyAddress(remote string) bool {
	r := strings.TrimSpace(remote)
	return r == "" || r == "*"
}

// MatchSensitive renvoie les ports sensibles couverts par localPorts
// (« 3389 », « 445,139 », « 5000-6000 », « RPC-EPMap »…), triés.
func MatchSensitive(localPorts string) []int {
	if AnyPort(localPorts) {
		return nil // traité par la règle « tous les ports »
	}
	set := map[int]bool{}
	for _, part := range strings.Split(localPorts, ",") {
		part = strings.TrimSpace(part)
		if strings.EqualFold(part, "RPC-EPMap") {
			set[135] = true
			continue
		}
		lo, hi, isRange := strings.Cut(part, "-")
		a, err1 := strconv.Atoi(strings.TrimSpace(lo))
		if err1 != nil {
			continue
		}
		b := a
		if isRange {
			if v, err := strconv.Atoi(strings.TrimSpace(hi)); err == nil {
				b = v
			}
		}
		for p := range SensitivePorts {
			if p >= a && p <= b {
				set[p] = true
			}
		}
	}
	out := make([]int, 0, len(set))
	for p := range set {
		out = append(out, p)
	}
	sort.Ints(out)
	return out
}

// Profiles traduit le masque NET_FW_PROFILE2 en noms PowerShell.
func Profiles(mask int64) []string {
	if mask == 0x7FFFFFFF || mask&7 == 7 {
		return []string{"Domain", "Private", "Public"}
	}
	var out []string
	for _, p := range []struct {
		bit  int64
		name string
	}{{1, "Domain"}, {2, "Private"}, {4, "Public"}} {
		if mask&p.bit != 0 {
			out = append(out, p.name)
		}
	}
	return out
}
