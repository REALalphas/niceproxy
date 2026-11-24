package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"
	"niceproxy/internal/model"
)

type Store struct{ db *sql.DB }

func Open(path string) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	s := &Store{db: db}
	_, err = db.Exec(`PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000;
	CREATE TABLE IF NOT EXISTS configuration (id INTEGER PRIMARY KEY CHECK(id=1), body TEXT NOT NULL, applied INTEGER NOT NULL DEFAULT 0);
	CREATE TABLE IF NOT EXISTS admin (id INTEGER PRIMARY KEY CHECK(id=1), password BLOB NOT NULL);
	CREATE TABLE IF NOT EXISTS sessions (hash TEXT PRIMARY KEY, expires INTEGER NOT NULL);
	CREATE TABLE IF NOT EXISTS integrations (name TEXT PRIMARY KEY, body BLOB NOT NULL);`)
	if err != nil {
		db.Close()
		return nil, err
	}
	if _, err = db.Exec("CREATE TABLE IF NOT EXISTS last_good (id INTEGER PRIMARY KEY CHECK(id=1), body TEXT NOT NULL)"); err != nil {
		db.Close()
		return nil, err
	}
	_ = os.Chmod(path, 0600)
	return s, nil
}
func (s *Store) Close() error { return s.db.Close() }

func (s *Store) Load() (model.Config, int64, error) {
	c := model.Config{HTTPRoutes: []model.HTTPRoute{}, DirectRules: []model.DirectRule{}}
	var body string
	var applied int64
	err := s.db.QueryRow("SELECT body, applied FROM configuration WHERE id=1").Scan(&body, &applied)
	if errors.Is(err, sql.ErrNoRows) {
		c.ApplyDefaults()
		return c, 0, nil
	}
	if err == nil {
		err = json.Unmarshal([]byte(body), &c)
	}
	c.ApplyDefaults()
	return c, applied, err
}
func (s *Store) Save(c model.Config) error {
	c = persistent(c)
	body, err := json.Marshal(c)
	if err != nil {
		return err
	}
	_, err = s.db.Exec("INSERT INTO configuration(id,body,applied) VALUES(1,?,-1) ON CONFLICT(id) DO UPDATE SET body=excluded.body,applied=-1", string(body))
	return err
}
func (s *Store) MarkApplied(c model.Config) error {
	c = persistent(c)
	body, err := json.Marshal(c)
	if err != nil {
		return err
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.Exec("UPDATE configuration SET applied=? WHERE id=1", c.Revision); err != nil {
		return err
	}
	if _, err = tx.Exec("INSERT INTO last_good(id,body) VALUES(1,?) ON CONFLICT(id) DO UPDATE SET body=excluded.body", string(body)); err != nil {
		return err
	}
	return tx.Commit()
}
func (s *Store) LastGood() (model.Config, error) {
	c := model.Config{HTTPRoutes: []model.HTTPRoute{}, DirectRules: []model.DirectRule{}}
	var body string
	err := s.db.QueryRow("SELECT body FROM last_good WHERE id=1").Scan(&body)
	if errors.Is(err, sql.ErrNoRows) {
		c.ApplyDefaults()
		return c, nil
	}
	if err != nil {
		return c, err
	}
	err = json.Unmarshal([]byte(body), &c)
	c.ApplyDefaults()
	return c, err
}
func (s *Store) Password() ([]byte, error) {
	var hash []byte
	err := s.db.QueryRow("SELECT password FROM admin WHERE id=1").Scan(&hash)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return hash, err
}
func (s *Store) Setup(hash []byte) error {
	_, err := s.db.Exec("INSERT INTO admin(id,password) VALUES(1,?)", hash)
	return err
}
func (s *Store) Session(hash string, expires time.Time) error {
	_, err := s.db.Exec("DELETE FROM sessions WHERE expires<?", time.Now().Unix())
	if err != nil {
		return err
	}
	_, err = s.db.Exec("INSERT INTO sessions(hash,expires) VALUES(?,?)", hash, expires.Unix())
	return err
}
func (s *Store) Authenticated(hash string) bool {
	var expires int64
	err := s.db.QueryRow("SELECT expires FROM sessions WHERE hash=?", hash).Scan(&expires)
	return err == nil && expires > time.Now().Unix()
}
func (s *Store) Logout(hash string) error {
	_, err := s.db.Exec("DELETE FROM sessions WHERE hash=?", hash)
	return err
}

// Integration stores provider data; secret material must be encrypted by its
// owner before it is passed here. Settings without credentials may be plain JSON.
func (s *Store) Integration(name string) ([]byte, error) {
	var body []byte
	err := s.db.QueryRow("SELECT body FROM integrations WHERE name=?", name).Scan(&body)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return body, err
}
func (s *Store) SetIntegration(name string, body []byte) error {
	if body == nil {
		_, err := s.db.Exec("DELETE FROM integrations WHERE name=?", name)
		return err
	}
	_, err := s.db.Exec("INSERT INTO integrations(name,body) VALUES(?,?) ON CONFLICT(name) DO UPDATE SET body=excluded.body", name, body)
	return err
}

// Runtime observations never belong in durable desired or last-good state.
func persistent(c model.Config) model.Config {
	c.ApplyDefaults()
	c.DirectRules = append([]model.DirectRule{}, c.DirectRules...)
	for i := range c.DirectRules {
		c.DirectRules[i].Stats = nil
		c.DirectRules[i].Status = ""
		c.DirectRules[i].Error = ""
	}
	c.HTTPRoutes = append([]model.HTTPRoute{}, c.HTTPRoutes...)
	for i := range c.HTTPRoutes {
		c.HTTPRoutes[i].Status = ""
		c.HTTPRoutes[i].Error = ""
	}
	return c
}
