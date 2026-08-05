package exampleop

import (
	"embed"
	"html/template"
	"log/slog"
)

var (
	//go:embed templates
	templateFS embed.FS
	templates  = template.Must(template.ParseFS(templateFS, "templates/*.html"))
)

const (
	queryAuthRequestID = "authRequestID"
)

func errMsg(err error) string {
	if err == nil {
		return ""
	}
	slog.Error("template error", "error", err)
	return err.Error()
}
