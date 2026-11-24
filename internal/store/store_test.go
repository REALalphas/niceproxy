package store

import (
	"niceproxy/internal/model"
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

func TestLegacyOwnersAndRuntimeStatsNeverPersist(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "config.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err = s.db.Exec(`INSERT INTO configuration(id,body) VALUES(1,'{"revision":7,"httpRoutes":[],"directRules":[]}')`); err != nil {
		t.Fatal(err)
	}
	c, _, err := s.Load()
	if err != nil || c.PortOwners != (model.PortOwners{HTTP: "caddy", HTTPS: "caddy", HTTP3: "caddy"}) {
		t.Fatalf("legacy: %+v %v", c, err)
	}
	c.DirectRules = []model.DirectRule{{ID: "rule", Stats: &model.ConnectionStats{Accepted: 999}, Status: "healthy"}}
	if err = s.Save(c); err != nil {
		t.Fatal(err)
	}
	if err = s.MarkApplied(c); err != nil {
		t.Fatal(err)
	}
	loaded, _, _ := s.Load()
	good, _ := s.LastGood()
	for _, v := range []model.Config{loaded, good} {
		if v.DirectRules[0].Stats != nil || v.DirectRules[0].Status != "" {
			t.Fatalf("runtime persisted: %+v", v)
		}
	}
}
