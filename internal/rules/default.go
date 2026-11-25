package rules

import (
	"sync"

	"github.com/maxb1906/aplomb/assets"
)

var (
	defOnce sync.Once
	defCat  *Catalog
	defErr  error
)

// Default renvoie le catalogue embarqué.
func Default() (*Catalog, error) {
	defOnce.Do(func() { defCat, defErr = Parse(assets.Rules) })
	return defCat, defErr
}
