// Commande winres : génère les ressources Windows de l'exe (icône, manifeste,
// informations de version) dans cmd/aplomb/rsrc_windows_<arch>.syso, que
// « go build » lie automatiquement.
//
//	go run ./tools/winres -version 2.0.0
//
// Le manifeste déclare asInvoker (l'audit fonctionne sans droits admin, en
// mode dégradé), la prise en charge du DPI par écran (fenêtre nette) et les
// Common Controls v6 (boîtes de dialogue).
package main

import (
	"flag"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"strconv"

	"github.com/tc-hib/winres"
	"github.com/tc-hib/winres/version"
)

func main() {
	ver := flag.String("version", "dev", "version de l'exe (ex. 2.0.0 ou v2.0.0-3-gabc)")
	out := flag.String("out", filepath.Join("cmd", "aplomb"), "dossier des fichiers .syso")
	preview := flag.String("png", "", "écrit aussi l'icône 256×256 dans ce fichier PNG (aperçu)")
	flag.Parse()
	if *preview != "" {
		if err := writePNG(*preview, drawIcon(256)); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}
	if err := run(*ver, *out); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(ver, out string) error {
	rs := winres.ResourceSet{}
	var imgs []image.Image
	for _, s := range []int{16, 20, 24, 32, 40, 48, 64, 128, 256} {
		imgs = append(imgs, drawIcon(s))
	}
	icon, err := winres.NewIconFromImages(imgs)
	if err != nil {
		return err
	}
	if err := rs.SetIcon(winres.Name("APPICON"), icon); err != nil {
		return err
	}
	rs.SetManifest(winres.AppManifest{
		Identity:            winres.AssemblyIdentity{Name: "Aplomb"},
		Description:         "Aplomb",
		Compatibility:       winres.Win10AndAbove,
		ExecutionLevel:      winres.AsInvoker,
		DPIAwareness:        winres.DPIPerMonitorV2,
		UseCommonControlsV6: true,
		LongPathAware:       true,
	})
	num := numeric(ver)
	vi := version.Info{}
	vi.SetFileVersion(num)
	vi.SetProductVersion(num)
	for k, v := range map[string]string{
		version.ProductName:      "Aplomb",
		version.FileDescription:  "Aplomb - Windows security configuration audit (read-only)",
		version.CompanyName:      "maxb1906",
		version.LegalCopyright:   "GPL-3.0-or-later",
		version.OriginalFilename: "aplomb.exe",
		version.InternalName:     "aplomb",
		version.ProductVersion:   ver,
		version.FileVersion:      ver,
	} {
		if err := vi.Set(0, k, v); err != nil {
			return err
		}
	}
	rs.SetVersionInfo(vi)
	for name, arch := range map[string]winres.Arch{"amd64": winres.ArchAMD64, "arm64": winres.ArchARM64} {
		p := filepath.Join(out, "rsrc_windows_"+name+".syso")
		f, err := os.Create(p)
		if err != nil {
			return err
		}
		if err := rs.WriteObject(f, arch); err != nil {
			f.Close()
			return err
		}
		if err := f.Close(); err != nil {
			return err
		}
	}
	return nil
}

func writePNG(path string, img image.Image) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	if err := png.Encode(f, img); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

var reVersion = regexp.MustCompile(`^v?(\d+)(?:\.(\d+))?(?:\.(\d+))?`)

// numeric extrait « 2.0.0.0 » d'une version de type v2.0.0-3-gabc (0.0.0.0 si absente).
func numeric(v string) string {
	m := reVersion.FindStringSubmatch(v)
	parts := [3]int{}
	for i := 0; m != nil && i < 3; i++ {
		parts[i], _ = strconv.Atoi(m[i+1])
	}
	return fmt.Sprintf("%d.%d.%d.0", parts[0], parts[1], parts[2])
}

// drawIcon dessine le fil à plomb (mêmes formes que frontend/src/lib/Logo.svelte,
// repère 64×64), avec anticrénelage par suréchantillonnage 4×4.
func drawIcon(size int) image.Image {
	img := image.NewNRGBA(image.Rect(0, 0, size, size))
	blue := [3]float64{0x2f, 0x6f, 0xde}
	const ss = 4
	for y := 0; y < size; y++ {
		for x := 0; x < size; x++ {
			var bg, fg float64
			for sy := 0; sy < ss; sy++ {
				for sx := 0; sx < ss; sx++ {
					u := (float64(x) + (float64(sx)+.5)/ss) * 64 / float64(size)
					v := (float64(y) + (float64(sy)+.5)/ss) * 64 / float64(size)
					if !inRoundRect(u, v, 4, 4, 60, 60, 14) {
						continue
					}
					if white(u, v) {
						fg++
					} else {
						bg++
					}
				}
			}
			n := float64(ss * ss)
			a := (bg + fg) / n
			if a == 0 {
				continue
			}
			mix := fg / (bg + fg)
			c := func(i int) uint8 { return uint8(math.Round(blue[i]*(1-mix) + 255*mix)) }
			img.SetNRGBA(x, y, color.NRGBA{c(0), c(1), c(2), uint8(math.Round(a * 255))})
		}
	}
	return img
}

func white(u, v float64) bool {
	// Barre horizontale (20,14)→(44,14), épaisseur 4, bouts ronds.
	if distSeg(u, v, 20, 14, 44, 14) <= 2 {
		return true
	}
	// Fil (32,14)→(32,30), épaisseur 2,5 (au moins 1,6 pour rester visible en petit).
	if math.Abs(u-32) <= 1.6 && v >= 14 && v <= 30 {
		return true
	}
	// Plomb : losange (32,29) (41,38) (32,52) (23,38).
	return inPoly(u, v, [][2]float64{{32, 29}, {41, 38}, {32, 52}, {23, 38}})
}

func inRoundRect(u, v, x0, y0, x1, y1, r float64) bool {
	if u < x0 || u > x1 || v < y0 || v > y1 {
		return false
	}
	cx := math.Max(x0+r, math.Min(u, x1-r))
	cy := math.Max(y0+r, math.Min(v, y1-r))
	return (u-cx)*(u-cx)+(v-cy)*(v-cy) <= r*r
}

func distSeg(px, py, ax, ay, bx, by float64) float64 {
	dx, dy := bx-ax, by-ay
	t := math.Max(0, math.Min(1, ((px-ax)*dx+(py-ay)*dy)/(dx*dx+dy*dy)))
	return math.Hypot(px-(ax+t*dx), py-(ay+t*dy))
}

func inPoly(x, y float64, pts [][2]float64) bool {
	in := false
	for i, j := 0, len(pts)-1; i < len(pts); j, i = i, i+1 {
		if (pts[i][1] > y) != (pts[j][1] > y) && x < (pts[j][0]-pts[i][0])*(y-pts[i][1])/(pts[j][1]-pts[i][1])+pts[i][0] {
			in = !in
		}
	}
	return in
}
