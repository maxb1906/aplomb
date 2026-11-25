package report

import (
	"time"
)

func formatDate(t time.Time, lang string) string {
	if t.IsZero() {
		return "—"
	}
	if lang == "en" {
		return t.Local().Format("2006-01-02")
	}
	return t.Local().Format("02/01/2006")
}

func formatDateTime(t time.Time, lang string) string {
	if t.IsZero() {
		return "—"
	}
	if lang == "en" {
		return t.Local().Format("2006-01-02 15:04")
	}
	return t.Local().Format("02/01/2006 15:04")
}
