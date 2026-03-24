package unit

import (
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

func TestSkillScanEndpointConfigured(t *testing.T) {
	// Verify config has scanner settings that the /v1/skill/scan endpoint needs
	cfg := config.DefaultConfig()

	if cfg.Scanners.SkillScanner.Binary == "" {
		t.Error("expected default skill-scanner binary to be set")
	}
	if cfg.Scanners.SkillScanner.Binary != "skill-scanner" {
		t.Errorf("expected 'skill-scanner', got %q", cfg.Scanners.SkillScanner.Binary)
	}
}
