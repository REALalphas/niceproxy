package store

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"niceproxy/internal/model"
)

func tempStore(t *testing.T) (*Store, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "state", "config.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s, path
}

func TestStoreAuthLifecycle(t *testing.T) {
	s, path := tempStore(t)
	if got, err := s.Password(); err != nil || got != nil {
		t.Fatalf("empty password: %q %v", got, err)
	}
	if err := s.Setup([]byte("hash")); err != nil {
		t.Fatal(err)
	}
	if err := s.Setup([]byte("replacement")); err == nil {
		t.Fatal("duplicate setup accepted")
	}
	now := time.Now()
	if err := s.Session("live", now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := s.Session("expired", now.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	var expiredRows int
	if err := s.db.QueryRow("SELECT count(*) FROM sessions WHERE hash='expired'").Scan(&expiredRows); err != nil || expiredRows != 1 {
		t.Fatalf("expired test session was not inserted: rows=%d, error=%v", expiredRows, err)
	}
	if s.Authenticated("expired") {
		t.Fatal("expired session accepted")
	}
	if err := s.Session("new", now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := s.db.QueryRow("SELECT count(*) FROM sessions WHERE hash='expired'").Scan(&expiredRows); err != nil || expiredRows != 0 {
		t.Fatalf("expired rows: %d %v", expiredRows, err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if got, err := reopened.Password(); err != nil || string(got) != "hash" {
		t.Fatalf("persisted password: %q %v", got, err)
	}
	for key, want := range map[string]bool{"live": true, "new": true, "expired": false, "missing": false} {
		if got := reopened.Authenticated(key); got != want {
			t.Errorf("Authenticated(%q) = %v, want %v", key, got, want)
		}
	}
	if err := reopened.Logout("live"); err != nil {
		t.Fatal(err)
	}
	if reopened.Authenticated("live") || !reopened.Authenticated("new") {
		t.Fatal("logout must revoke only the requested session")
	}
}

func TestStoreIntegrationLifecycle(t *testing.T) {
	s, _ := tempStore(t)
	const name = "provider"
	if got, err := s.Integration(name); err != nil || got != nil {
		t.Fatalf("empty integration: %q %v", got, err)
	}
	for _, value := range []string{"first", "replacement"} {
		if err := s.SetIntegration(name, []byte(value)); err != nil {
			t.Fatal(err)
		}
		if got, err := s.Integration(name); err != nil || string(got) != value {
			t.Fatalf("integration: %q %v, want %q", got, err, value)
		}
	}
	if err := s.SetIntegration(name, nil); err != nil {
		t.Fatal(err)
	}
	if got, err := s.Integration(name); err != nil || got != nil {
		t.Fatalf("deleted integration: %q %v", got, err)
	}
}

func TestMarkAppliedRollsBackWhenLastGoodWriteFails(t *testing.T) {
	s, _ := tempStore(t)
	if got, err := s.LastGood(); err != nil || got.Revision != 0 || got.PortOwners.HTTP != "caddy" {
		t.Fatalf("initial last-good: %+v %v", got, err)
	}
	initial := model.Config{Revision: 1, PanelDomain: "old.example"}
	if err := s.Save(initial); err != nil {
		t.Fatal(err)
	}
	if err := s.MarkApplied(initial); err != nil {
		t.Fatal(err)
	}
	desired := model.Config{Revision: 2, PanelDomain: "new.example"}
	if err := s.Save(desired); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec("CREATE TRIGGER fail_last_good BEFORE UPDATE ON last_good BEGIN SELECT RAISE(ABORT, 'test failure'); END"); err != nil {
		t.Fatal(err)
	}
	if err := s.MarkApplied(desired); err == nil {
		t.Fatal("MarkApplied succeeded despite failed last-good write")
	}
	loaded, applied, err := s.Load()
	if err != nil || applied != -1 || loaded.Revision != desired.Revision || loaded.PanelDomain != desired.PanelDomain {
		t.Fatalf("desired state: %+v, applied=%d, error=%v", loaded, applied, err)
	}
	good, err := s.LastGood()
	if err != nil || good.Revision != initial.Revision || good.PanelDomain != initial.PanelDomain {
		t.Fatalf("last-good state: %+v, error=%v", good, err)
	}
	if _, err := s.db.Exec("DROP TRIGGER fail_last_good"); err != nil {
		t.Fatal(err)
	}
	if err := s.MarkApplied(desired); err != nil {
		t.Fatal(err)
	}
	_, applied, err = s.Load()
	if err != nil || applied != desired.Revision {
		t.Fatalf("retry applied=%d, error=%v", applied, err)
	}
	good, err = s.LastGood()
	if err != nil || good.Revision != desired.Revision || good.PanelDomain != desired.PanelDomain {
		t.Fatalf("retried last-good state: %+v, error=%v", good, err)
	}
}

func TestOpenRejectsNonDatabaseAndInvalidParent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "not-a-database")
	if err := os.WriteFile(path, []byte("not a SQLite database"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, candidate := range []string{path, filepath.Join(path, "config.db")} {
		if s, err := Open(candidate); err == nil {
			_ = s.Close()
			t.Errorf("Open(%q) accepted an invalid path", candidate)
		}
	}
}
