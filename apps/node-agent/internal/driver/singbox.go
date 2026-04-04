package driver

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
)

type Driver interface {
	Validate(ctx context.Context, cfg map[string]any) error
	Apply(ctx context.Context, cfg map[string]any) error
	Restart(ctx context.Context) error
	Reload(ctx context.Context) error
}

type SingboxDriver struct {
	ConfigPath string
}

func New(configPath string) *SingboxDriver {
	return &SingboxDriver{ConfigPath: configPath}
}

func (d *SingboxDriver) Validate(ctx context.Context, cfg map[string]any) error {
	if err := d.writeConfig(cfg); err != nil {
		return err
	}
	cmd := exec.CommandContext(ctx, "sing-box", "check", "-c", d.ConfigPath)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func (d *SingboxDriver) Apply(ctx context.Context, cfg map[string]any) error {
	if err := d.writeConfig(cfg); err != nil {
		return err
	}
	return d.Reload(ctx)
}

func (d *SingboxDriver) Restart(ctx context.Context) error {
	cmd := exec.CommandContext(ctx, "sh", "-c", "pkill sing-box || true && sing-box run -c "+d.ConfigPath+" &")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func (d *SingboxDriver) Reload(ctx context.Context) error {
	cmd := exec.CommandContext(ctx, "sh", "-c", "pkill -HUP sing-box || sing-box run -c "+d.ConfigPath+" &")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func (d *SingboxDriver) writeConfig(cfg map[string]any) error {
	if err := os.MkdirAll(filepath.Dir(d.ConfigPath), 0o755); err != nil {
		return err
	}
	body, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(d.ConfigPath, body, 0o644)
}

