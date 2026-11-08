package model

import (
	"fmt"
	"strings"
	"unicode"
)

// NormalizeRoutePath accepts a literal, decoded URL path prefix. No glob or
// Caddy placeholder syntax is exposed through the routing API.
func NormalizeRoutePath(value string) (string, error) {
	if value == "" {
		return "/", nil
	}
	if !strings.HasPrefix(value, "/") || len(value) > 2048 || strings.ContainsAny(value, "*?#[%\\{}") || strings.Contains(value, "//") {
		return "", fmt.Errorf("path must be a literal prefix starting with /, without query, fragments, escapes or wildcards")
	}
	for _, c := range value {
		if unicode.IsSpace(c) || unicode.IsControl(c) {
			return "", fmt.Errorf("path must not contain whitespace or control characters")
		}
	}
	for _, segment := range strings.Split(value, "/") {
		if segment == "." || segment == ".." {
			return "", fmt.Errorf("path must not contain dot segments")
		}
	}
	if value != "/" {
		value = strings.TrimSuffix(value, "/")
	}
	return value, nil
}
