package driver

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"syscall"
	"time"
)

type Driver interface {
	Validate(ctx context.Context, cfg map[string]any) error
	Apply(ctx context.Context, cfg map[string]any) error
	EnsureRunning(ctx context.Context, cfg map[string]any) error
	Restart(ctx context.Context) error
	Reload(ctx context.Context) error
}

type SingboxDriver struct {
	ConfigPath string
	mu         sync.Mutex
	cmd        *exec.Cmd
	waitDone   chan error
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
	return d.Restart(ctx)
}

func (d *SingboxDriver) EnsureRunning(ctx context.Context, cfg map[string]any) error {
	d.mu.Lock()
	running := d.isRunningLocked()
	d.mu.Unlock()
	if running {
		return nil
	}
	return d.Apply(ctx, cfg)
}

func (d *SingboxDriver) Restart(ctx context.Context) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if err := d.stopLocked(); err != nil {
		return err
	}
	cmd := exec.Command("sing-box", "run", "-c", d.ConfigPath)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return err
	}
	done := make(chan error, 1)
	d.cmd = cmd
	d.waitDone = done
	go func() {
		err := cmd.Wait()
		done <- err
		d.mu.Lock()
		if d.cmd == cmd {
			d.cmd = nil
			d.waitDone = nil
		}
		d.mu.Unlock()
		if err != nil {
			log.Printf("sing-box exited: %v", err)
		}
	}()
	timer := time.NewTimer(300 * time.Millisecond)
	defer timer.Stop()
	select {
	case err := <-done:
		d.cmd = nil
		d.waitDone = nil
		if err == nil {
			return fmt.Errorf("sing-box exited immediately")
		}
		return err
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func (d *SingboxDriver) Reload(ctx context.Context) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.isRunningLocked() {
		d.mu.Unlock()
		err := d.Restart(ctx)
		d.mu.Lock()
		return err
	}
	return d.cmd.Process.Signal(syscall.SIGHUP)
}

func (d *SingboxDriver) isRunningLocked() bool {
	return d.cmd != nil && d.cmd.Process != nil && d.cmd.ProcessState == nil
}

func (d *SingboxDriver) stopLocked() error {
	if !d.isRunningLocked() {
		return nil
	}
	proc := d.cmd.Process
	done := d.waitDone
	_ = proc.Signal(syscall.SIGTERM)
	timer := time.NewTimer(3 * time.Second)
	defer timer.Stop()
	select {
	case <-done:
		d.cmd = nil
		d.waitDone = nil
		return nil
	case <-timer.C:
		_ = proc.Kill()
		if done != nil {
			<-done
		}
		d.cmd = nil
		d.waitDone = nil
		return nil
	}
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
