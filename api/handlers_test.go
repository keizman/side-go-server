package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	miniredis "github.com/alicebob/miniredis/v2"
	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
	redisClient "github.com/yourname/side-go-server/internal/redis"
)

func setupBusinessRedis(t *testing.T) *miniredis.Miniredis {
	t.Helper()

	mr := miniredis.RunT(t)
	redisClient.Client = redis.NewClient(&redis.Options{Addr: mr.Addr()})
	redisClient.Ctx = context.Background()
	t.Cleanup(func() {
		_ = redisClient.Client.Close()
	})
	return mr
}

func TestLogin(t *testing.T) {
	gin.SetMode(gin.TestMode)
	mr := setupBusinessRedis(t)

	t.Run("Given invalid payload When login called Then responds 400", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/login", strings.NewReader(`{"email":"bad"`))
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = req

		Login(c)

		if w.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d", w.Code)
		}
	})

	t.Run("Given valid login and guest token exists When login called Then token is removed and refresh action returned", func(t *testing.T) {
		tempID := "tmp-1"
		guestKey := "token:tmp-1:tmp-1"
		mr.Set(guestKey, "guest-token")

		req := httptest.NewRequest(http.MethodPost, "/api/login", strings.NewReader(`{"email":"u@example.com","password":"secret1"}`))
		req.Header.Set("x-temp-id", tempID)
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = req

		Login(c)

		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", w.Code)
		}

		if mr.Exists(guestKey) {
			t.Fatalf("expected guest token key %s to be deleted", guestKey)
		}

		var resp LoginResponse
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatalf("failed to decode response: %v", err)
		}
		if resp.UserID != "user_u@example.com" || resp.Email != "u@example.com" || resp.Action != "refresh_token" {
			t.Fatalf("unexpected response: %+v", resp)
		}
		tierKey := "user:tier:user_u@example.com"
		tierValue, err := mr.Get(tierKey)
		if err != nil {
			t.Fatalf("expected user tier key %s, got error: %v", tierKey, err)
		}
		if tierValue != "2" {
			t.Fatalf("expected user tier value 2, got %s", tierValue)
		}
	})
}

func TestLogout(t *testing.T) {
	gin.SetMode(gin.TestMode)
	mr := setupBusinessRedis(t)

	t.Run("Given no auth context When logout called Then responds 400", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest(http.MethodPost, "/api/logout", nil)

		Logout(c)

		if w.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d", w.Code)
		}
	})

	t.Run("Given authenticated user When logout called Then token for current device is removed", func(t *testing.T) {
		key := "token:user-1:device-1"
		mr.Set(key, "token-value")

		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest(http.MethodPost, "/api/logout", nil)
		c.Set("verified_uid", "user-1")
		c.Set("verified_device_id", "device-1")

		Logout(c)

		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", w.Code)
		}
		if mr.Exists(key) {
			t.Fatalf("expected key %s to be deleted", key)
		}
	})
}

func TestLogoutAllDevices(t *testing.T) {
	gin.SetMode(gin.TestMode)
	mr := setupBusinessRedis(t)

	t.Run("Given no uid in context When logout all called Then responds 400", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest(http.MethodPost, "/api/logout_all", nil)

		LogoutAllDevices(c)

		if w.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d", w.Code)
		}
	})

	t.Run("Given multiple device tokens for user When logout all called Then all tokens are removed", func(t *testing.T) {
		mr.Set("token:user-2:dev-1", "t1")
		mr.Set("token:user-2:dev-2", "t2")
		mr.Set("token:other:dev-9", "t3")

		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest(http.MethodPost, "/api/logout_all", nil)
		c.Set("verified_uid", "user-2")

		LogoutAllDevices(c)

		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", w.Code)
		}
		if mr.Exists("token:user-2:dev-1") || mr.Exists("token:user-2:dev-2") {
			t.Fatalf("expected all user-2 tokens removed")
		}
		if !mr.Exists("token:other:dev-9") {
			t.Fatalf("expected other user's token to remain")
		}

		var body map[string]interface{}
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
			t.Fatalf("failed to decode response: %v", err)
		}
		if body["devices_cleared"].(float64) != 2 {
			t.Fatalf("expected devices_cleared=2, got %v", body["devices_cleared"])
		}
	})
}

func TestBusinessPlaceholderEndpoints(t *testing.T) {
	gin.SetMode(gin.TestMode)

	t.Run("Given verified context When translate called Then returns uid and role", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest(http.MethodPost, "/api/translate", nil)
		c.Set("verified_uid", "user-9")
		c.Set("verified_role", "admin")

		Translate(c)

		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", w.Code)
		}

		var body map[string]string
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
			t.Fatalf("failed to decode response: %v", err)
		}
		if body["uid"] != "user-9" || body["role"] != "admin" {
			t.Fatalf("unexpected response: %+v", body)
		}
	})

	t.Run("Given verified context When profile called Then returns uid and role", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest(http.MethodGet, "/api/user/profile", nil)
		c.Set("verified_uid", "user-7")
		c.Set("verified_role", "user")

		GetProfile(c)

		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", w.Code)
		}

		var body map[string]string
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
			t.Fatalf("failed to decode response: %v", err)
		}
		if body["uid"] != "user-7" || body["role"] != "user" {
			t.Fatalf("unexpected response: %+v", body)
		}
	})
}
