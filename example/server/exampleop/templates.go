package exampleop

import (
	"embed"
	"html/template"

	"github.com/sirupsen/logrus"
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
	logrus.Error(err)
	return err.Error()
}
