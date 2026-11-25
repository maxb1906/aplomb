//go:build !windows

package collect

import "os"

// Elevated indique que le processus tourne avec les droits administrateur.
func Elevated() bool { return os.Geteuid() == 0 }
