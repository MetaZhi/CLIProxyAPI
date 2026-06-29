package management

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
)

func TestGetRoutingExpiryPriorityWindow_Default(t *testing.T) {
	gin.SetMode(gin.TestMode)
	rec := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(rec)

	handler := &Handler{cfg: &config.Config{}}
	handler.GetRoutingExpiryPriorityWindow(ctx)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	var payload map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	if payload["expiry-priority-window"] != "5h" {
		t.Fatalf("expiry-priority-window = %q, want %q", payload["expiry-priority-window"], "5h")
	}
}

func TestPutRoutingExpiryPriorityWindow_RejectsInvalidDuration(t *testing.T) {
	gin.SetMode(gin.TestMode)
	rec := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(rec)
	ctx.Request = httptest.NewRequest(http.MethodPut, "/v0/management/routing/expiry-priority-window", bytes.NewBufferString(`{"value":"0"}`))
	ctx.Request.Header.Set("Content-Type", "application/json")

	handler := &Handler{cfg: &config.Config{}}
	handler.PutRoutingExpiryPriorityWindow(ctx)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

func TestPutRoutingExpiryPriorityWindow_PersistsValue(t *testing.T) {
	gin.SetMode(gin.TestMode)
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(configPath, []byte("routing:\n  strategy: round-robin\n"), 0o644); err != nil {
		t.Fatalf("os.WriteFile() error = %v", err)
	}

	rec := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(rec)
	ctx.Request = httptest.NewRequest(http.MethodPut, "/v0/management/routing/expiry-priority-window", bytes.NewBufferString(`{"value":"6h"}`))
	ctx.Request.Header.Set("Content-Type", "application/json")

	handler := &Handler{
		cfg:            &config.Config{},
		configFilePath: configPath,
	}
	handler.PutRoutingExpiryPriorityWindow(ctx)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if handler.cfg.Routing.ExpiryPriorityWindow != "6h" {
		t.Fatalf("handler.cfg.Routing.ExpiryPriorityWindow = %q, want %q", handler.cfg.Routing.ExpiryPriorityWindow, "6h")
	}
}
