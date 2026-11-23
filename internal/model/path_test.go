package model

import "testing"

func TestNormalizeRoutePath(t *testing.T) {
	for input, want := range map[string]string{"": "/", "/": "/", "/api/": "/api", "/api/v1": "/api/v1", "/café": "/café"} {
		got, err := NormalizeRoutePath(input)
		if err != nil || got != want {
			t.Fatalf("%q -> %q %v", input, got, err)
		}
	}
	for _, input := range []string{"api", "/api/*", "/api?x=1", "/api#part", "/api/%2F", "/a//b", "/a/../b", "/a/./b", "/{env.HOME}", "/a\nb", "/a\\b"} {
		if _, err := NormalizeRoutePath(input); err == nil {
			t.Fatalf("accepted %q", input)
		}
	}
}
