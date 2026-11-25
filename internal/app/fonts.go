package app

import (
	_ "embed"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

// Vazirmatn (SIL Open Font License, see fonts/OFL-vazirmatn.txt) is the
// built-in panel font.
//
//go:embed fonts/vazirmatn.woff2
var vazirmatn []byte

// The panel prefers Yekan when its files are present in the "fonts"
// directory next to the config (e.g. /etc/mirage/fonts). Commercial fonts
// are never bundled; the owner copies their licensed files there.
func (a *App) fontsDir() string { return filepath.Join(filepath.Dir(a.path), "fonts") }

// yekanFile picks the Yekan file for a CSS weight (400 or 700).
func (a *App) yekanFile(weight string) string {
	var files []string
	for _, ext := range []string{"woff2", "woff", "ttf"} {
		m, _ := filepath.Glob(filepath.Join(a.fontsDir(), "*."+ext))
		files = append(files, m...)
	}
	var regular, bold, any string
	for _, f := range files {
		n := strings.ToLower(filepath.Base(f))
		if !strings.Contains(n, "yekan") {
			continue
		}
		if any == "" {
			any = f
		}
		switch {
		case strings.Contains(n, "regular") && regular == "":
			regular = f
		case strings.Contains(n, "bold") && !strings.Contains(n, "extra") && !strings.Contains(n, "demi") &&
			!strings.Contains(n, "semi") && bold == "":
			bold = f
		}
	}
	if regular == "" {
		regular = any
	}
	if weight == "700" && bold != "" {
		return bold
	}
	return regular
}

func (a *App) serveFont(w http.ResponseWriter, r *http.Request, name string) {
	w.Header().Set("Cache-Control", "public, max-age=86400")
	switch name {
	case "vazirmatn.woff2":
		w.Header().Set("Content-Type", "font/woff2")
		_, _ = w.Write(vazirmatn)
	case "yekan-400", "yekan-700":
		f := a.yekanFile(strings.TrimPrefix(name, "yekan-"))
		if f == "" {
			http.NotFound(w, r)
			return
		}
		b, err := os.ReadFile(f)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		ct := map[string]string{".woff2": "font/woff2", ".woff": "font/woff", ".ttf": "font/ttf"}[strings.ToLower(filepath.Ext(f))]
		w.Header().Set("Content-Type", ct)
		_, _ = w.Write(b)
	default:
		http.NotFound(w, r)
	}
}
