package cloudflare

import (
	"context"
	"errors"
	"net/http"
	"slices"
)

type ZoneSetting struct {
	ID       string `json:"id"`
	Value    string `json:"value"`
	Editable bool   `json:"editable"`
}

var (
	ErrInvalidZoneSetting = errors.New("Invalid zone, setting, or setting value")
	ErrReadOnlySetting    = errors.New("Cloudflare reports this setting as read-only for the selected zone")
)

func zoneSettingValues(id string) []string {
	switch id {
	case "ssl":
		return []string{"off", "flexible", "full", "strict", "origin_pull"}
	case "always_use_https", "automatic_https_rewrites":
		return []string{"on", "off"}
	}
	return nil
}

func (m *Manager) ReadZoneSetting(ctx context.Context, zoneID, id string) (ZoneSetting, error) {
	if !validHex(zoneID) || zoneSettingValues(id) == nil {
		return ZoneSetting{}, ErrInvalidZoneSetting
	}
	setting, err := m.zoneSetting(ctx, http.MethodGet, zoneID, id, nil)
	return setting, withPermission(err, "Zone Settings Read")
}

func (m *Manager) WriteZoneSetting(ctx context.Context, zoneID, id, value string) (ZoneSetting, error) {
	if !validHex(zoneID) || !slices.Contains(zoneSettingValues(id), value) {
		return ZoneSetting{}, ErrInvalidZoneSetting
	}
	m.op.Lock()
	defer m.op.Unlock()
	current, err := m.ReadZoneSetting(ctx, zoneID, id)
	if err != nil || current.Value == value {
		return current, err
	}
	if !current.Editable {
		return ZoneSetting{}, ErrReadOnlySetting
	}
	setting, err := m.zoneSetting(ctx, http.MethodPatch, zoneID, id, struct {
		Value string `json:"value"`
	}{value})
	if err != nil {
		return ZoneSetting{}, withPermission(err, "Zone Settings Write (Edit)")
	}
	if setting.Value != value {
		return ZoneSetting{}, errors.New("Cloudflare returned a different setting value. Refresh the zone settings before retrying")
	}
	return setting, nil
}

func (m *Manager) zoneSetting(ctx context.Context, method, zoneID, id string, body any) (ZoneSetting, error) {
	var result ZoneSetting
	if _, err := m.api(ctx, method, "/zones/"+zoneID+"/settings/"+id, body, &result); err != nil {
		return ZoneSetting{}, err
	}
	if result.ID != id || result.Value == "" {
		return ZoneSetting{}, errors.New("Cloudflare returned an invalid zone setting")
	}
	return result, nil
}
