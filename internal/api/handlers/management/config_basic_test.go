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

func TestGetRoutingMinimumQuotaPercent_Default(t *testing.T) {
	gin.SetMode(gin.TestMode)
	rec := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(rec)

	handler := &Handler{cfg: &config.Config{}}
	handler.GetRoutingMinimumQuotaPercent(ctx)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	var payload map[string]float64
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	if payload["minimum-quota-percent"] != 20 {
		t.Fatalf("minimum-quota-percent = %v, want 20", payload["minimum-quota-percent"])
	}
}

func TestPutRoutingMinimumQuotaPercent_AcceptsRange(t *testing.T) {
	gin.SetMode(gin.TestMode)

	for _, value := range []string{"0", "20", "100"} {
		t.Run(value, func(t *testing.T) {
			dir := t.TempDir()
			configPath := filepath.Join(dir, "config.yaml")
			if err := os.WriteFile(configPath, []byte("routing:\n  strategy: round-robin\n"), 0o644); err != nil {
				t.Fatalf("os.WriteFile() error = %v", err)
			}

			rec := httptest.NewRecorder()
			ctx, _ := gin.CreateTestContext(rec)
			ctx.Request = httptest.NewRequest(http.MethodPut, "/v0/management/routing/minimum-quota-percent", bytes.NewBufferString(`{"value":`+value+`}`))
			ctx.Request.Header.Set("Content-Type", "application/json")

			handler := &Handler{
				cfg:            &config.Config{},
				configFilePath: configPath,
			}
			handler.PutRoutingMinimumQuotaPercent(ctx)

			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusOK, rec.Body.String())
			}
			if handler.cfg.Routing.MinimumQuotaPercent == nil {
				t.Fatalf("handler.cfg.Routing.MinimumQuotaPercent = nil, want %s", value)
			}
			var want float64
			if err := json.Unmarshal([]byte(value), &want); err != nil {
				t.Fatalf("json.Unmarshal(value) error = %v", err)
			}
			if *handler.cfg.Routing.MinimumQuotaPercent != want {
				t.Fatalf("handler.cfg.Routing.MinimumQuotaPercent = %v, want %v", *handler.cfg.Routing.MinimumQuotaPercent, want)
			}
		})
	}
}

func TestPutRoutingMinimumQuotaPercent_RejectsInvalidValues(t *testing.T) {
	gin.SetMode(gin.TestMode)

	for _, body := range []string{
		`{"value":-1}`,
		`{"value":101}`,
		`{"value":"20"}`,
		`{"value":null}`,
	} {
		t.Run(body, func(t *testing.T) {
			rec := httptest.NewRecorder()
			ctx, _ := gin.CreateTestContext(rec)
			ctx.Request = httptest.NewRequest(http.MethodPut, "/v0/management/routing/minimum-quota-percent", bytes.NewBufferString(body))
			ctx.Request.Header.Set("Content-Type", "application/json")

			handler := &Handler{cfg: &config.Config{}}
			handler.PutRoutingMinimumQuotaPercent(ctx)

			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadRequest)
			}
		})
	}
}
