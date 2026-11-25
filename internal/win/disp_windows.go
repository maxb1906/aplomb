package win

import (
	"fmt"

	"github.com/go-ole/go-ole"
	"github.com/go-ole/go-ole/oleutil"
)

// Disp simplifie l'accès à un objet COM Automation (IDispatch).
type Disp struct{ d *ole.IDispatch }

// NewObject crée un objet COM par son ProgID (COM doit être initialisé : WithCOM).
func NewObject(progID string) (*Disp, error) {
	unk, err := oleutil.CreateObject(progID)
	if err != nil {
		return nil, fmt.Errorf("%s : %w", progID, err)
	}
	defer unk.Release()
	d, err := unk.QueryInterface(ole.IID_IDispatch)
	if err != nil {
		return nil, err
	}
	return &Disp{d}, nil
}

// Release libère l'objet.
func (o *Disp) Release() {
	if o != nil && o.d != nil {
		o.d.Release()
		o.d = nil
	}
}

// Raw renvoie l'IDispatch sous-jacent.
func (o *Disp) Raw() *ole.IDispatch { return o.d }

// Call appelle une méthode.
func (o *Disp) Call(name string, args ...any) (*ole.VARIANT, error) {
	return oleutil.CallMethod(o.d, name, args...)
}

// Get lit une propriété (avec paramètres éventuels).
func (o *Disp) Get(name string, args ...any) (*ole.VARIANT, error) {
	return oleutil.GetProperty(o.d, name, args...)
}

func toDisp(v *ole.VARIANT, err error) (*Disp, error) {
	if err != nil {
		return nil, err
	}
	d := v.ToIDispatch()
	if d == nil {
		return nil, fmt.Errorf("not an object")
	}
	return &Disp{d}, nil
}

// Obj lit une propriété objet.
func (o *Disp) Obj(name string, args ...any) (*Disp, error) { return toDisp(o.Get(name, args...)) }

// CallObj appelle une méthode qui renvoie un objet.
func (o *Disp) CallObj(name string, args ...any) (*Disp, error) { return toDisp(o.Call(name, args...)) }

// Str lit une propriété texte ("" si absente ou nulle).
func (o *Disp) Str(name string, args ...any) string {
	v, err := o.Get(name, args...)
	if err != nil {
		return ""
	}
	defer v.Clear()
	switch x := v.Value().(type) {
	case string:
		return x
	case nil:
		return ""
	default:
		return fmt.Sprint(x)
	}
}

// Int lit une propriété numérique.
func (o *Disp) Int(name string, args ...any) (int64, bool) {
	v, err := o.Get(name, args...)
	if err != nil {
		return 0, false
	}
	defer v.Clear()
	return VariantInt(v.Value())
}

// Bool lit une propriété booléenne.
func (o *Disp) Bool(name string, args ...any) (bool, bool) {
	v, err := o.Get(name, args...)
	if err != nil {
		return false, false
	}
	defer v.Clear()
	switch x := v.Value().(type) {
	case bool:
		return x, true
	default:
		n, ok := VariantInt(x)
		return n != 0, ok
	}
}

// VariantInt convertit une valeur de VARIANT en entier.
func VariantInt(v any) (int64, bool) {
	switch x := v.(type) {
	case int8:
		return int64(x), true
	case int16:
		return int64(x), true
	case int32:
		return int64(x), true
	case int64:
		return x, true
	case int:
		return int64(x), true
	case uint8:
		return int64(x), true
	case uint16:
		return int64(x), true
	case uint32:
		return int64(x), true
	case uint64:
		return int64(x), true
	case bool:
		if x {
			return 1, true
		}
		return 0, true
	}
	return 0, false
}

// ForEach parcourt une collection COM.
func (o *Disp) ForEach(fn func(item *Disp) error) error {
	return oleutil.ForEach(o.d, func(v *ole.VARIANT) error {
		d := v.ToIDispatch()
		if d == nil {
			return nil
		}
		// L'élément énuméré porte une référence : on la libère après usage.
		defer d.Release()
		return fn(&Disp{d})
	})
}
