package config

import (
	"bytes"
	"fmt"

	"github.com/BurntSushi/toml"
)

// Marshal encodes c as TOML that Parse reads back to an equal Config.
// Empty fields are left out, so defaults stay implicit. Comments in the
// file the config came from are not preserved.
func Marshal(c *Config) ([]byte, error) {
	var buf bytes.Buffer
	buf.WriteString("# Marmot node configuration. Written by the Marmot panel; comments are not kept.\n\n")
	if err := toml.NewEncoder(&buf).Encode(c); err != nil {
		return nil, fmt.Errorf("encode config: %w", err)
	}
	return buf.Bytes(), nil
}
