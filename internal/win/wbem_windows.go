package win

import (
	"github.com/go-ole/go-ole"
	"github.com/go-ole/go-ole/oleutil"
)

// WbemQuery exécute une requête WQL et appelle fn pour chaque objet. À appeler
// dans WithCOM. Contrairement à WMI(), donne accès aux méthodes des objets.
func WbemQuery(namespace, query string, fn func(obj *Disp) error) error {
	loc, err := NewObject("WbemScripting.SWbemLocator")
	if err != nil {
		return err
	}
	defer loc.Release()
	svc, err := loc.CallObj("ConnectServer", ".", namespace)
	if err != nil {
		return err
	}
	defer svc.Release()
	set, err := svc.CallObj("ExecQuery", query)
	if err != nil {
		return err
	}
	defer set.Release()
	return set.ForEach(fn)
}

// ExecMethod appelle une méthode WMI avec des paramètres nommés et renvoie
// l'objet des paramètres de sortie.
func (o *Disp) ExecMethod(method string, in map[string]any) (*Disp, error) {
	methods, err := o.Obj("Methods_")
	if err != nil {
		return nil, err
	}
	defer methods.Release()
	m, err := methods.CallObj("Item", method)
	if err != nil {
		return nil, err
	}
	defer m.Release()
	var params *Disp
	if len(in) > 0 {
		def, err := m.Obj("InParameters")
		if err != nil {
			return nil, err
		}
		defer def.Release()
		params, err = def.CallObj("SpawnInstance_")
		if err != nil {
			return nil, err
		}
		defer params.Release()
		for k, v := range in {
			if _, err := oleutil.PutProperty(params.d, k, v); err != nil {
				return nil, err
			}
		}
	}
	if params != nil {
		return o.CallObj("ExecMethod_", method, params.d)
	}
	return o.CallObj("ExecMethod_", method)
}

// Strings lit une propriété tableau de chaînes.
func (o *Disp) Strings(name string) ([]string, bool) {
	v, err := o.Get(name)
	if err != nil {
		return nil, false
	}
	defer v.Clear()
	if v.VT == ole.VT_NULL || v.VT == ole.VT_EMPTY {
		return []string{}, true
	}
	arr := v.ToArray()
	if arr == nil {
		if s, ok := v.Value().(string); ok {
			return []string{s}, true
		}
		return nil, false
	}
	out := []string{}
	for _, x := range arr.ToValueArray() {
		if s, ok := x.(string); ok {
			out = append(out, s)
		}
	}
	return out, true
}

// Ints lit une propriété tableau numérique.
func (o *Disp) Ints(name string) ([]int64, bool) {
	v, err := o.Get(name)
	if err != nil {
		return nil, false
	}
	defer v.Clear()
	if v.VT == ole.VT_NULL || v.VT == ole.VT_EMPTY {
		return []int64{}, true
	}
	arr := v.ToArray()
	if arr == nil {
		return nil, false
	}
	var out []int64
	for _, x := range arr.ToValueArray() {
		if n, ok := VariantInt(x); ok {
			out = append(out, n)
		}
	}
	return out, true
}
