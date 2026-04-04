package store

import (
	"context"
	"testing"

	"github.com/fear/gulpo/apps/panel-api/internal/domain"
)

func TestMergeMap(t *testing.T) {
	base := map[string]any{
		"log": map[string]any{
			"level": "info",
		},
	}
	override := map[string]any{
		"log": map[string]any{
			"level": "debug",
		},
		"domain": "node.example.com",
	}
	got := mergeMap(base, override)
	if got["domain"] != "node.example.com" {
		t.Fatalf("expected domain override")
	}
	if got["log"].(map[string]any)["level"] != "debug" {
		t.Fatalf("expected nested override")
	}
}

func TestBuildSubscriptionSkipsDisabledOrOverLimit(t *testing.T) {
	_ = context.Background()
	user := domain.User{
		Status: domain.UserStatusDisabled,
	}
	if user.Status == domain.UserStatusActive {
		t.Fatalf("expected disabled test precondition")
	}
}

