package collect

import "golang.org/x/sys/windows"

// Elevated indique que le processus tourne avec les droits administrateur.
func Elevated() bool { return windows.GetCurrentProcessToken().IsElevated() }
