package config

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"strings"

	"github.com/BurntSushi/toml"
)

// Loaded is a parsed, defaulted and validated configuration together with
// the hash of the source text (used for optimistic locking by the API).
type Loaded struct {
	Config   *Config
	Version  string
	Warnings []Issue
}

// LoadFile reads, parses and validates a configuration file.
func LoadFile(path string) (*Loaded, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	return Parse(data)
}

// Parse decodes TOML strictly (unknown keys are errors), applies defaults
// and validates. It never returns a Config that failed validation.
func Parse(data []byte) (*Loaded, error) {
	var c Config
	md, err := toml.NewDecoder(bytes.NewReader(data)).Decode(&c)
	if err != nil {
		return nil, &ValidationError{Issues: []Issue{{Severity: SeverityError, Path: "", Message: err.Error()}}}
	}
	if und := md.Undecoded(); len(und) > 0 {
		issues := make([]Issue, 0, len(und))
		for _, k := range und {
			if isOptionsKey(k) {
				continue
			}
			issues = append(issues, Issue{Severity: SeverityError, Path: k.String(), Message: "unknown key"})
		}
		if len(issues) > 0 {
			return nil, &ValidationError{Issues: issues}
		}
	}
	c.ApplyDefaults()
	issues := c.Validate()
	if errs := filter(issues, SeverityError); len(errs) > 0 {
		return nil, &ValidationError{Issues: errs}
	}
	return &Loaded{Config: &c, Version: Version(data), Warnings: filter(issues, SeverityWarning)}, nil
}

// Version returns the content hash used as the config version.
func Version(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:8])
}

// isOptionsKey reports whether k lies inside a free-form transport options
// table, whose keys are validated by the transport itself.
func isOptionsKey(k toml.Key) bool {
	for _, part := range k {
		if part == "options" {
			return true
		}
	}
	return false
}

func filter(issues []Issue, sev Severity) []Issue {
	var out []Issue
	for _, i := range issues {
		if i.Severity == sev {
			out = append(out, i)
		}
	}
	return out
}

// ValidationError lists every problem found in a configuration.
type ValidationError struct {
	Issues []Issue
}

func (e *ValidationError) Error() string {
	parts := make([]string, len(e.Issues))
	for i, is := range e.Issues {
		parts[i] = is.String()
	}
	return "invalid config: " + strings.Join(parts, "; ")
}
