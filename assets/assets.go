// Package assets regroupe les fichiers embarqués dans l'exécutable :
// traductions, et plus tard règles d'audit, modèles de rapport et CSS.
package assets

import "embed"

// I18n contient les fichiers de traduction assets/i18n/<langue>.json.
//
//go:embed i18n/*.json
var I18n embed.FS
