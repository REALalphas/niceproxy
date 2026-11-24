package caddy

import (
	"bytes"
	"context"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"niceproxy/internal/model"
)

const operationTimeout = 10 * time.Second

type Manager struct {
	mu       sync.Mutex // Serialize every mutation, including process lifecycle changes.
	options  Options
	client   *http.Client
	cmd      *exec.Cmd
	waitDone chan struct{}
	waitErr  error // Written before waitDone closes; read only after receiving waitDone.
	done     chan error
	closing  atomic.Bool
	closed   bool
}

func New(o Options) *Manager {
	o = defaults(o)
	transport := &http.Transport{Proxy: nil, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", filepath.Join(o.RuntimeDir, "caddy.sock"))
	}}
	return &Manager{options: o, client: &http.Client{Transport: transport, Timeout: operationTimeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, done: make(chan error, 1)}
}

// Done reports an unexpected child exit (including a successful exit). The child
// is always reaped, and this channel closes once it has exited.
func (m *Manager) Done() <-chan error { return m.done }

func (m *Manager) CertificateStatus(domain string) model.CertificateStatus {
	status := model.CertificateStatus{Configured: domain != "", Domain: domain, State: "not_configured"}
	if domain == "" {
		return status
	}
	state, err := m.CertificateState(context.Background(), domain)
	status.State = "pending"
	switch state {
	case "valid":
		status.State = "issued"
	case "expired":
		status.State = "expired"
	case "missing", "not_yet_issued":
		status.State = "pending"
	default:
		status.State = "error"
	}
	if err != nil {
		status.Error = err.Error()
	}
	return status
}

func (m *Manager) running() bool {
	if m.cmd == nil {
		return false
	}
	select {
	case <-m.waitDone:
		return false
	default:
		return true
	}
}

func (m *Manager) request(ctx context.Context, method, path string, body []byte) error {
	req, err := http.NewRequestWithContext(ctx, method, "http://localhost"+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	res, err := m.client.Do(req)
	if err != nil {
		return fmt.Errorf("Caddy admin request: %w", err)
	}
	defer res.Body.Close()
	// Do not include Caddy response bodies: they may contain config or credentials.
	_, _ = io.Copy(io.Discard, io.LimitReader(res.Body, 1<<20))
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("Caddy admin returned HTTP %d", res.StatusCode)
	}
	return nil
}

func (m *Manager) Healthy(ctx context.Context) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return !m.closed && m.running() && m.request(ctx, http.MethodGet, "/config/", nil) == nil
}

func privateDir(path string) error {
	if err := os.MkdirAll(path, 0700); err != nil {
		return err
	}
	st, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !st.IsDir() {
		return fmt.Errorf("private path is not a directory")
	}
	return os.Chmod(path, 0700)
}

// stage writes and syncs before contacting Caddy, so ordinary filesystem errors
// cannot cause an applied config to be mistaken for a rejected load.
func (m *Manager) stage(config []byte) (string, error) {
	f, err := os.CreateTemp(m.options.RuntimeDir, ".caddy-*.json")
	if err != nil {
		return "", err
	}
	name := f.Name()
	if _, err = f.Write(config); err == nil {
		err = f.Sync()
	}
	if e := f.Close(); err == nil {
		err = e
	}
	if err != nil {
		_ = os.Remove(name)
		return "", err
	}
	return name, nil
}

func (m *Manager) persist(name string) error {
	if err := os.Rename(name, filepath.Join(m.options.RuntimeDir, "caddy.json")); err != nil {
		return fmt.Errorf("Caddy config applied, but last-good config could not be saved: %w", err)
	}
	return nil
}

func (m *Manager) Start(ctx context.Context, routes []model.HTTPRoute, owners ...model.PortOwners) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed || m.cmd != nil {
		return errors.New("Caddy manager already started or closed")
	}
	if len(owners) > 0 {
		m.options.PortOwners = owners[0]
	}
	config, err := BuildConfig(m.options, routes)
	if err != nil {
		return err
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	if err = privateDir(m.options.RuntimeDir); err != nil {
		return err
	}
	if err = privateDir(m.options.DataDir); err != nil {
		return err
	}
	socket := filepath.Join(m.options.RuntimeDir, "caddy.sock")
	if st, e := os.Lstat(socket); e == nil {
		if st.Mode()&os.ModeSocket == 0 {
			return errors.New("refusing to remove non-socket Caddy admin path")
		}
		conn, e := net.DialTimeout("unix", socket, 200*time.Millisecond)
		if e == nil {
			_ = conn.Close()
			return errors.New("Caddy admin socket is already in use")
		}
		if !errors.Is(e, syscall.ECONNREFUSED) {
			return fmt.Errorf("cannot establish that Caddy admin socket is stale: %w", e)
		}
		if err = os.Remove(socket); err != nil {
			return err
		}
	} else if !errors.Is(e, os.ErrNotExist) {
		return e
	}
	name, err := m.stage(config)
	if err != nil {
		return err
	}
	defer os.Remove(name)
	cmd := exec.Command(m.options.Binary, "run", "--config", name)
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGTERM}
	// Keep runtime diagnostics (bind errors, certificate issuance and reloads)
	// available in container logs. Configs never contain credentials.
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	for _, entry := range os.Environ() {
		if !strings.HasPrefix(entry, "XDG_DATA_HOME=") && !strings.HasPrefix(entry, "XDG_CONFIG_HOME=") {
			cmd.Env = append(cmd.Env, entry)
		}
	}
	cmd.Env = append(cmd.Env, "XDG_DATA_HOME="+m.options.DataDir, "XDG_CONFIG_HOME="+m.options.RuntimeDir)
	if err = cmd.Start(); err != nil {
		return fmt.Errorf("launch Caddy: %w", err)
	}
	m.cmd = cmd
	m.waitDone = make(chan struct{})
	go func() {
		err := cmd.Wait()
		m.waitErr = err
		if !m.closing.Load() {
			if err == nil {
				err = errors.New("Caddy exited unexpectedly")
			}
			m.done <- err
		}
		close(m.waitDone)
		close(m.done)
	}()
	startup, cancel := context.WithTimeout(ctx, operationTimeout)
	defer cancel()
	ticker := time.NewTicker(25 * time.Millisecond)
	defer ticker.Stop()
	for {
		if m.running() && m.request(startup, http.MethodGet, "/config/", nil) == nil {
			if err = os.Chmod(socket, 0600); err != nil {
				break
			}
			if err = m.persist(name); err == nil {
				return nil
			}
			break
		}
		select {
		case <-m.waitDone:
			return fmt.Errorf("Caddy exited during startup: %v", m.waitErr)
		case <-startup.Done():
			err = fmt.Errorf("Caddy startup: %w", startup.Err())
		case <-ticker.C:
			continue
		}
		break
	}
	m.closing.Store(true)
	_ = cmd.Process.Kill()
	<-m.waitDone
	return err
}

func (m *Manager) Apply(ctx context.Context, routes []model.HTTPRoute) error {
	return m.apply(ctx, routes, nil)
}
func (m *Manager) ApplyConfig(ctx context.Context, cfg model.Config) error {
	m.mu.Lock()
	m.options.PanelDomain = cfg.PanelDomain
	m.options.PanelDomainProxied = cfg.PanelDomainProxied
	m.mu.Unlock()
	return m.apply(ctx, cfg.HTTPRoutes, &cfg.PortOwners)
}
func (m *Manager) ValidateConfig(cfg model.Config) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	o := m.options
	o.PortOwners = cfg.PortOwners
	o.PanelDomain = cfg.PanelDomain
	o.PanelDomainProxied = cfg.PanelDomainProxied
	_, err := BuildConfig(o, cfg.HTTPRoutes)
	return err
}
func (m *Manager) PublicPorts() (int, int) { return m.options.HTTPPort, m.options.HTTPSPort }
func (m *Manager) SetPanelDomain(domain string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.options.PanelDomain = domain
}

// CertificateState inspects Caddy's persisted certificate store. It never
// treats an unrelated certificate as valid for the requested SNI.
func (m *Manager) CertificateState(ctx context.Context, host string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var found bool
	var firstErr error
	var firstState string
	root := filepath.Join(m.options.DataDir, "caddy")
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			if os.IsNotExist(err) {
				return nil
			}
			return err
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if d.IsDir() || (filepath.Ext(path) != ".crt" && filepath.Ext(path) != ".pem") {
			return nil
		}
		if strings.Contains(path, string(filepath.Separator)+"authorities"+string(filepath.Separator)) || strings.EqualFold(filepath.Base(path), "root.crt") {
			return nil
		}
		b, e := os.ReadFile(path)
		if e != nil {
			return nil
		}
		block, _ := pem.Decode(b)
		if block == nil || block.Type != "CERTIFICATE" {
			return nil
		}
		found = true
		key, _ := os.ReadFile(strings.TrimSuffix(path, filepath.Ext(path)) + ".key")
		if len(key) == 0 {
			// Caddy also stores local/root CA certificates without private
			// keys. Only a leaf candidate for this SNI is an invalid missing-key
			// condition.
			if strings.Contains(strings.ToLower(path), string(filepath.Separator)+strings.ToLower(host)+string(filepath.Separator)) {
				found = true
				if firstErr == nil {
					firstState = "invalid"
					firstErr = errors.New("certificate private key is missing")
				}
			}
			return nil
		}
		state, e := ValidateCertificate(b, key, host, time.Now())
		if state == "valid" {
			return filepath.SkipAll
		}
		if firstErr == nil {
			firstErr = e
			firstState = state
		}
		return nil
	})
	if err != nil && !errors.Is(err, filepath.SkipAll) {
		return "invalid", err
	}
	if !found {
		return "missing", nil
	}
	if firstErr != nil {
		return firstState, firstErr
	}
	return "invalid", errors.New("no certificate matches requested SNI")
}
func (m *Manager) apply(ctx context.Context, routes []model.HTTPRoute, owners *model.PortOwners) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed || !m.running() {
		return errors.New("Caddy is not running")
	}
	o := m.options
	if owners != nil {
		o.PortOwners = *owners
	}
	config, err := BuildConfig(o, routes)
	if err != nil {
		return err
	}
	name, err := m.stage(config)
	if err != nil {
		return err
	}
	defer os.Remove(name)
	load, cancel := context.WithTimeout(ctx, operationTimeout)
	defer cancel()
	if err = m.request(load, http.MethodPost, "/load", config); err != nil {
		// A connection failure or timeout may happen after Caddy accepted the load.
		// Keep last-good untouched and avoid claiming that the live config reverted.
		return fmt.Errorf("Caddy load not confirmed; last-good config retained: %w", err)
	}
	return m.persist(name)
}

func (m *Manager) Close(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return nil
	}
	m.closed = true
	m.closing.Store(true)
	defer m.client.CloseIdleConnections()
	if m.cmd == nil {
		close(m.done)
		return nil
	}
	if m.running() {
		_ = m.cmd.Process.Signal(syscall.SIGTERM)
	}
	select {
	case <-m.waitDone:
		return nil
	case <-ctx.Done():
		_ = m.cmd.Process.Kill()
		<-m.waitDone // Kill, then reap; never leave a zombie behind.
		return ctx.Err()
	}
}
