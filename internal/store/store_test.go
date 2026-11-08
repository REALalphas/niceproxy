package store

import (
	"path/filepath"
	"testing"
)

func TestLegacyHTTPRoutesDefaultToRoot(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	legacy := `{"revision":7,"httpRoutes":[{"id":"legacy","host":"app.example.com","target":"http://127.0.0.1:3000","enabled":true}],"directRules":[]}`
	if _, err = s.db.Exec("INSERT INTO configuration(id,body,applied) VALUES(1,?,7)", legacy); err != nil {
		t.Fatal(err)
	}
	if _, err = s.db.Exec("INSERT INTO last_good(id,body) VALUES(1,?)", legacy); err != nil {
		t.Fatal(err)
	}
	c, _, err := s.Load()
	if err != nil {
		t.Fatal(err)
	}
	g, err := s.LastGood()
	if err != nil {
		t.Fatal(err)
	}
	if c.HTTPRoutes[0].Path != "/" || c.HTTPRoutes[0].TLS != "auto" || g.HTTPRoutes[0].Path != "/" || g.HTTPRoutes[0].StripPrefix {
		t.Fatal(c, g)
	}
}
