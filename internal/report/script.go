package report

import "io"

// Script écrit le script de remédiation (complété à l'étape 11).
func Script(w io.Writer, r *Report, o Options) error {
	_, err := io.WriteString(w, "# Aplomb\r\n")
	return err
}
