package api

import (
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
)

// staticHandler serves the built panel from api.web_root. Paths that are
// not files get index.html, so client-side routes survive a reload.
// Hashed assets are cached for a year; index.html never is, so a new
// build is picked up at once.
func (s *Server) staticHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		root := s.cfg.Node.Config().API.WebRoot
		if root == "" {
			writeError(w, http.StatusNotFound, "not_found", "the panel is not installed (api.web_root is empty)")
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "")
			return
		}
		// Clean of a rooted path removes every "..", so file stays under root.
		clean := path.Clean("/" + r.URL.Path)
		file := filepath.Join(root, filepath.FromSlash(clean))
		if st, err := os.Stat(file); err == nil && !st.IsDir() { //nolint:gosec // see above
			if strings.HasPrefix(clean, "/assets/") {
				w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
			}
			http.ServeFile(w, r, file) //nolint:gosec // file is under root, see above
			return
		}
		if path.Ext(clean) != "" {
			http.NotFound(w, r) // a missing asset is a 404, not the app
			return
		}
		w.Header().Set("Cache-Control", "no-cache")
		http.ServeFile(w, r, filepath.Join(root, "index.html"))
	})
}
