package report

import (
	"fmt"
	htmltemplate "html/template"
	"io"
	"strings"
	texttemplate "text/template"
	"time"

	"github.com/maxb1906/aplomb/assets"
	"github.com/maxb1906/aplomb/internal/i18n"
)

func funcs(tr *i18n.Translator) map[string]any {
	return map[string]any{
		"t": func(key string, pairs ...any) string {
			ss := make([]string, len(pairs))
			for i, p := range pairs {
				ss[i] = fmt.Sprint(p)
			}
			return tr.T(key, ss...)
		},
		"levelLabel": func(l string) string { return tr.T("level." + l) },
		"datetime":   func(t time.Time) string { return formatDateTime(t, tr.Lang()) },
		"date":       func(t time.Time) string { return formatDate(t, tr.Lang()) },
		"md": func(s string) string {
			return strings.NewReplacer("|", `\|`, "\n", " ", "\r", "").Replace(s)
		},
	}
}

// HTML écrit le rapport HTML autonome (CSS et script en ligne).
func HTML(w io.Writer, r *Report, o Options) error {
	css, err := assets.Report.ReadFile("report/report.css")
	if err != nil {
		return err
	}
	src, err := assets.Report.ReadFile("report/report.html")
	if err != nil {
		return err
	}
	fm := htmltemplate.FuncMap(funcs(o.Translator))
	fm["css"] = func() htmltemplate.CSS { return htmltemplate.CSS(css) }
	// Le logo est une image locale encodée en data: (pas d'URL externe).
	fm["safeURL"] = func(s string) htmltemplate.URL {
		if strings.HasPrefix(s, "data:image/") {
			return htmltemplate.URL(s)
		}
		return ""
	}
	t, err := htmltemplate.New("report").Funcs(fm).Parse(string(src))
	if err != nil {
		return err
	}
	return t.Execute(w, BuildView(r, o))
}

// Markdown écrit le rapport Markdown.
func Markdown(w io.Writer, r *Report, o Options) error {
	src, err := assets.Report.ReadFile("report/report.md")
	if err != nil {
		return err
	}
	t, err := texttemplate.New("report").Funcs(texttemplate.FuncMap(funcs(o.Translator))).Parse(string(src))
	if err != nil {
		return err
	}
	return t.Execute(w, BuildView(r, o))
}
