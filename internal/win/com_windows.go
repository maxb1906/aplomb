package win

import (
	"errors"
	"runtime"

	"github.com/go-ole/go-ole"
	"github.com/yusufpapurcu/wmi"
)

// WithCOM exécute fn sur un thread système verrouillé où COM est initialisé.
func WithCOM(fn func() error) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if err := ole.CoInitializeEx(0, ole.COINIT_MULTITHREADED); err != nil {
		var oe *ole.OleError
		if !errors.As(err, &oe) {
			return err
		}
		switch oe.Code() {
		case 0x00000001: // S_FALSE : déjà initialisé sur ce thread
			defer ole.CoUninitialize()
		case 0x80010106: // RPC_E_CHANGED_MODE : initialisé dans un autre mode, utilisable
		default:
			return err
		}
	} else {
		defer ole.CoUninitialize()
	}
	return fn()
}

// WMI exécute une requête WQL dans namespace et remplit dst (slice de structs).
// Les champs du struct absents de la classe ne sont pas une erreur.
func WMI(namespace, query string, dst any) error {
	err := wmi.QueryNamespace(query, dst, namespace)
	var fm *wmi.ErrFieldMismatch
	if errors.As(err, &fm) {
		return nil
	}
	return err
}

// IsAccessDenied reconnaît un refus d'accès WMI/COM ou Win32.
func IsAccessDenied(err error) bool {
	if err == nil {
		return false
	}
	var oe *ole.OleError
	if errors.As(err, &oe) {
		switch oe.Code() {
		case 0x80041003, 0x80070005: // WBEM_E_ACCESS_DENIED, E_ACCESSDENIED
			return true
		}
		if se, ok := oe.SubError().(ole.EXCEPINFO); ok && (se.SCODE() == 0x80041003 || se.SCODE() == 0x80070005) {
			return true
		}
	}
	msg := err.Error()
	return containsAny(msg, "Access denied", "Access is denied", "0x80041003", "0x80070005", "Accès refusé")
}

// IsNotFound reconnaît un espace de noms ou une classe WMI absente.
func IsNotFound(err error) bool {
	if err == nil {
		return false
	}
	return containsAny(err.Error(), "0x8004100E", "0x80041010", "Invalid namespace", "Invalid class", "Espace de noms non valide", "Classe non valide")
}
