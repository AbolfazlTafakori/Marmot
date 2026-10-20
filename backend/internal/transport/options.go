package transport

import "fmt"

// StringOption returns opts[key] as a string, or def when it is absent.
func StringOption(opts map[string]any, key, def string) (string, error) {
	v, ok := opts[key]
	if !ok {
		return def, nil
	}
	s, ok := v.(string)
	if !ok {
		return "", fmt.Errorf("option %q must be a string", key)
	}
	return s, nil
}

// BoolOption returns opts[key] as a bool, or def when it is absent.
func BoolOption(opts map[string]any, key string, def bool) (bool, error) {
	v, ok := opts[key]
	if !ok {
		return def, nil
	}
	b, ok := v.(bool)
	if !ok {
		return false, fmt.Errorf("option %q must be a boolean", key)
	}
	return b, nil
}
