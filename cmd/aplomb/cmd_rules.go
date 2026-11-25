package main

import (
	"fmt"

	"github.com/maxb1906/aplomb/internal/rules"
)

// cmdRules liste le catalogue des règles.
func cmdRules(e *env, _ []string) int {
	cat, err := rules.Default()
	if err != nil {
		return e.fail(err)
	}
	for _, r := range cat.Rules {
		admin := ""
		if r.Admin {
			admin = " [admin]"
		}
		fmt.Fprintf(e.stdout, "%-8s %-9s %-8s %s%s\n", r.ID, r.Category, e.T("level."+r.Level), r.Text(e.tr.Lang()).Title, admin)
	}
	return 0
}
