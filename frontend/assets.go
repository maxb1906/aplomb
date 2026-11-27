// Package frontend embarque l'interface graphique compilée (frontend/dist).
//
// dist est produit par « npm run build » (make frontend) ; sans lui, seul le
// fichier .gitkeep est embarqué et l'exe se replie sur la ligne de commande.
package frontend

import (
	"embed"
	"io/fs"
)

//go:embed all:dist
var dist embed.FS

// Dist renvoie les fichiers de l'interface, à la racine.
func Dist() fs.FS {
	sub, err := fs.Sub(dist, "dist")
	if err != nil {
		panic(err)
	}
	return sub
}

// Built indique que l'interface a été compilée (index.html présent).
func Built() bool {
	_, err := fs.Stat(Dist(), "index.html")
	return err == nil
}
