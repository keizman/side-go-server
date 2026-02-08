package middleware

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestVerifySignature(t *testing.T) {
	gin.SetMode(gin.TestMode)

	t.Run("Given missing bearer header When request arrives Then responds 401", func(t *testing.T) {
		r := gin.New()
		r.POST("/api/translate", VerifySignature(), func(c *gin.Context) {
			c.Status(http.StatusOK)
		})

		req := httptest.NewRequest(http.MethodPost, "/api/translate", strings.NewReader(`{"q":"hi"}`))
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		if w.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401, got %d", w.Code)
		}
	})

	t.Run("Given missing required headers When request arrives Then responds 400", func(t *testing.T) {
		r := gin.New()
		r.POST("/api/translate", VerifySignature(), func(c *gin.Context) {
			c.Status(http.StatusOK)
		})

		req := httptest.NewRequest(http.MethodPost, "/api/translate", strings.NewReader(`{"q":"hi"}`))
		req.Header.Set("Authorization", "Bearer token-123")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		if w.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d", w.Code)
		}
	})

	t.Run("Given invalid signature When request arrives Then responds 403", func(t *testing.T) {
		r := gin.New()
		r.POST("/api/translate", VerifySignature(), func(c *gin.Context) {
			c.Status(http.StatusOK)
		})

		req := httptest.NewRequest(http.MethodPost, "/api/translate", strings.NewReader(`{"q":"hi"}`))
		req.Header.Set("Authorization", "Bearer token-123")
		req.Header.Set("x-timestamp", "1700000000")
		req.Header.Set("x-temp-id", "temp-1")
		req.Header.Set("x-sign", "wrong-signature")

		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		if w.Code != http.StatusForbidden {
			t.Fatalf("expected 403, got %d", w.Code)
		}
	})

	t.Run("Given valid POST signature When middleware verifies Then request passes and body is reusable", func(t *testing.T) {
		r := gin.New()
		r.POST("/api/translate", VerifySignature(), func(c *gin.Context) {
			body, err := io.ReadAll(c.Request.Body)
			if err != nil {
				t.Fatalf("failed to read downstream body: %v", err)
			}
			c.JSON(http.StatusOK, gin.H{
				"uid":       c.GetString("verified_uid"),
				"role":      c.GetString("verified_role"),
				"device_id": c.GetString("verified_device_id"),
				"body":      string(body),
			})
		})

		timestamp := "1700000000"
		tempID := "device-abc"
		token := "token-123"
		body := `{"text":"hello"}`
		payload := fmt.Sprintf("%s|%s|%s", sha256Hex([]byte(body)), timestamp, tempID)
		sign := hmacSHA256(payload, token)

		req := httptest.NewRequest(http.MethodPost, "/api/translate", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("x-timestamp", timestamp)
		req.Header.Set("x-temp-id", tempID)
		req.Header.Set("x-sign", sign)
		req.Header.Set("X-Verified-UID", "u-1")
		req.Header.Set("X-Verified-Role", "user")
		req.Header.Set("X-Verified-DeviceID", tempID)

		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", w.Code)
		}

		var resp map[string]string
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatalf("failed to decode response: %v", err)
		}

		if resp["uid"] != "u-1" || resp["role"] != "user" || resp["device_id"] != tempID {
			t.Fatalf("unexpected verified headers in context: %+v", resp)
		}
		if resp["body"] != body {
			t.Fatalf("expected downstream body %q, got %q", body, resp["body"])
		}
	})

	t.Run("Given valid GET signature with unordered query When middleware verifies Then request passes", func(t *testing.T) {
		r := gin.New()
		r.GET("/api/profile", VerifySignature(), func(c *gin.Context) {
			c.Status(http.StatusOK)
		})

		timestamp := "1700000000"
		tempID := "device-abc"
		token := "token-123"
		sorted := "a=1&b=1&b=2"
		payload := fmt.Sprintf("%s|%s|%s", sorted, timestamp, tempID)
		sign := hmacSHA256(payload, token)

		req := httptest.NewRequest(http.MethodGet, "/api/profile?b=2&a=1&b=1", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("x-timestamp", timestamp)
		req.Header.Set("x-temp-id", tempID)
		req.Header.Set("x-sign", sign)

		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", w.Code)
		}
	})
}

func TestSortQueryString(t *testing.T) {
	tests := []struct {
		name  string
		query url.Values
		want  string
	}{
		{
			name:  "Given empty query Then return empty string",
			query: url.Values{},
			want:  "",
		},
		{
			name: "Given unordered multi-values Then sort keys and values",
			query: url.Values{
				"b": {"2", "1"},
				"a": {"3"},
			},
			want: "a=3&b=1&b=2",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := sortQueryString(tt.query)
			if got != tt.want {
				t.Fatalf("expected %q, got %q", tt.want, got)
			}
		})
	}
}
