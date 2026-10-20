package api

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"

	"marmot/internal/config"
)

// apiError carries an HTTP status out of a config mutation.
type apiError struct {
	status int
	code   string
	msg    string
}

func (e *apiError) Error() string { return e.msg }

// invalidConfig is returned when a configuration fails validation; it is
// answered with 422 and the issues.
type invalidConfig struct{ result validationResult }

func (e *invalidConfig) Error() string { return "invalid configuration" }

func resultFrom(err error) validationResult {
	res := validationResult{Valid: false}
	var ve *config.ValidationError
	if errors.As(err, &ve) {
		for _, is := range ve.Issues {
			res.Issues = append(res.Issues, issueView{Severity: string(is.Severity), Path: is.Path, Message: is.Message})
		}
		return res
	}
	res.Issues = []issueView{{Severity: "error", Path: "", Message: err.Error()}}
	return res
}

// readConfigFile returns the file's text and version.
func (s *Server) readConfigFile() ([]byte, string, error) {
	data, err := os.ReadFile(s.cfg.ConfigPath)
	if err != nil {
		return nil, "", fmt.Errorf("read config: %w", err)
	}
	return data, config.Version(data), nil
}

// applyConfig validates data, writes it atomically and applies it. The
// caller holds cfgMu. It returns warnings for parts that did not apply.
func (s *Server) applyConfig(data []byte) (*config.Loaded, []string, error) {
	loaded, err := config.Parse(data)
	if err != nil {
		return nil, nil, &invalidConfig{resultFrom(err)}
	}
	running := s.cfg.Node.Config()
	var issues []issueView
	if loaded.Config.Node.ID != running.Node.ID {
		issues = append(issues, issueView{"error", "node.id", "changing the node id requires a restart; edit the file and restart"})
	}
	if loaded.Config.Node.IdentityKeyFile != running.Node.IdentityKeyFile {
		issues = append(issues, issueView{"error", "node.identity_key_file", "changing the identity requires a restart"})
	}
	if len(issues) > 0 {
		return nil, nil, &invalidConfig{validationResult{Valid: false, Issues: issues}}
	}
	if err := writeFileAtomic(s.cfg.ConfigPath, data); err != nil {
		return nil, nil, err
	}
	warnings := restartOnlyWarnings(running, loaded.Config)
	if err := s.cfg.Node.Reload(loaded.Config); err != nil {
		warnings = append(warnings, strings.Split(err.Error(), "\n")...)
	}
	return loaded, warnings, nil
}

// restartOnlyWarnings names settings that were saved but only take effect
// after a restart.
func restartOnlyWarnings(old, next *config.Config) []string {
	var w []string
	if !reflect.DeepEqual(old.API, next.API) {
		w = append(w, "api settings are saved and take effect after a restart")
	}
	if old.Telemetry.MetricsListen != next.Telemetry.MetricsListen {
		w = append(w, "telemetry.metrics_listen takes effect after a restart")
	}
	if !reflect.DeepEqual(old.Session, next.Session) {
		w = append(w, "session settings apply to new outbound sessions now and to inbound ones after a restart")
	}
	return w
}

// mutateConfig applies fn to the running file's configuration and saves
// the result. Comments in the file are not kept (ADR-0009).
func (s *Server) mutateConfig(fn func(*config.Config) error) (*config.Loaded, []string, error) {
	s.cfgMu.Lock()
	defer s.cfgMu.Unlock()
	data, _, err := s.readConfigFile()
	if err != nil {
		return nil, nil, err
	}
	cur, err := config.Parse(data)
	if err != nil {
		return nil, nil, &apiError{http.StatusConflict, "conflict",
			"marmot.toml on disk is invalid; fix it with PUT /config first: " + err.Error()}
	}
	if err := fn(cur.Config); err != nil {
		return nil, nil, err
	}
	out, err := config.Marshal(cur.Config)
	if err != nil {
		return nil, nil, err
	}
	return s.applyConfig(out)
}

// writeConfigError answers a failed mutation.
func (s *Server) writeConfigError(w http.ResponseWriter, err error) {
	var inv *invalidConfig
	var ae *apiError
	switch {
	case errors.As(err, &inv):
		writeJSON(w, http.StatusUnprocessableEntity, inv.result)
	case errors.As(err, &ae):
		writeError(w, ae.status, ae.code, ae.msg)
	default:
		s.internal(w, err)
	}
}

// writeFileAtomic replaces path with data so that a crash leaves either the
// old or the new file, never a mix. The file keeps its permissions.
func writeFileAtomic(path string, data []byte) error {
	mode := os.FileMode(0o600)
	if st, err := os.Stat(path); err == nil {
		mode = st.Mode().Perm()
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".marmot.toml.*")
	if err != nil {
		return fmt.Errorf("write config: %w", err)
	}
	name := tmp.Name()
	defer func() { _ = os.Remove(name) }() // no-op after a successful rename
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write config: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write config: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("write config: %w", err)
	}
	if err := os.Chmod(name, mode); err != nil {
		return fmt.Errorf("write config: %w", err)
	}
	if err := os.Rename(name, path); err != nil {
		return fmt.Errorf("write config: %w", err)
	}
	return nil
}
