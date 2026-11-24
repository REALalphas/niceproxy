package cloudflare

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// NewAutomationClient loads a mounted API token independently of browser OAuth.
func NewAutomationClient(path string) (*Manager, error) {
	if !filepath.IsAbs(path) {
		return nil, errors.New("Cloudflare automation token file must use an absolute path")
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, errors.New("cannot open Cloudflare automation token file")
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return nil, errors.New("Cloudflare automation token file must be a regular file")
	}
	b, err := io.ReadAll(io.LimitReader(f, 4097))
	token := strings.TrimSpace(string(b))
	if err != nil || len(b) > 4096 || token == "" || strings.ContainsAny(token, " \t\r\n") {
		return nil, errors.New("Cloudflare automation token file must contain one API token")
	}
	return New(Options{apiToken: token}, nil)
}
