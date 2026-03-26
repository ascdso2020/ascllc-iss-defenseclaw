package gateway

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/scanner"
)

func TestHandleCodeScan_ValidPath(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "vuln.py")
	if err := os.WriteFile(path, []byte("os.system(cmd)\n"), 0644); err != nil {
		t.Fatal(err)
	}

	api := testAPIServerWithConfig(t, "action")
	body, _ := json.Marshal(map[string]string{"path": path})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/scan/code", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	api.handleCodeScan(w, req)

	if w.Result().StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Result().StatusCode)
	}

	var result scanner.ScanResult
	if err := json.NewDecoder(w.Result().Body).Decode(&result); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if result.Scanner != "codeguard" {
		t.Errorf("scanner = %q, want codeguard", result.Scanner)
	}
	if len(result.Findings) == 0 {
		t.Error("expected findings for file with os.system")
	}
	if result.Findings[0].ID != "CG-EXEC-001" {
		t.Errorf("finding ID = %q, want CG-EXEC-001", result.Findings[0].ID)
	}
}

func TestHandleCodeScan_MissingPath(t *testing.T) {
	api := testAPIServerWithConfig(t, "action")
	body := `{"path": ""}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/scan/code", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	api.handleCodeScan(w, req)

	if w.Result().StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Result().StatusCode)
	}
}

func TestHandleCodeScan_NonexistentPath(t *testing.T) {
	api := testAPIServerWithConfig(t, "action")
	body := `{"path": "/nonexistent/does/not/exist.py"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/scan/code", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	api.handleCodeScan(w, req)

	if w.Result().StatusCode != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Result().StatusCode)
	}
}

func TestHandleCodeScan_CleanFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "clean.py")
	if err := os.WriteFile(path, []byte("print('hello')\n"), 0644); err != nil {
		t.Fatal(err)
	}

	api := testAPIServerWithConfig(t, "action")
	body, _ := json.Marshal(map[string]string{"path": path})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/scan/code", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	api.handleCodeScan(w, req)

	if w.Result().StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Result().StatusCode)
	}

	var result scanner.ScanResult
	if err := json.NewDecoder(w.Result().Body).Decode(&result); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(result.Findings) != 0 {
		t.Errorf("expected 0 findings for clean file, got %d", len(result.Findings))
	}
}
