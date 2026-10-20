package config

import "fmt"

// Severity of a validation issue.
type Severity string

// Severities: an error rejects the configuration, a warning does not.
const (
	SeverityError   Severity = "error"
	SeverityWarning Severity = "warning"
)

// Issue is one validation finding, addressed by a dotted config path.
type Issue struct {
	Severity Severity `json:"severity"`
	Path     string   `json:"path"`
	Message  string   `json:"message"`
}

func (i Issue) String() string {
	if i.Path == "" {
		return i.Message
	}
	return fmt.Sprintf("%s: %s", i.Path, i.Message)
}

// issues accumulates findings during validation.
type issues []Issue

func (is *issues) errf(path, format string, a ...any) {
	*is = append(*is, Issue{Severity: SeverityError, Path: path, Message: fmt.Sprintf(format, a...)})
}

func (is *issues) warnf(path, format string, a ...any) {
	*is = append(*is, Issue{Severity: SeverityWarning, Path: path, Message: fmt.Sprintf(format, a...)})
}
