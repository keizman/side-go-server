package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/yourname/side-go-server/repository"
)

type fakeConfRepo struct {
	getFn    func(uzid, key string) (json.RawMessage, time.Time, error)
	upsertFn func(uzid, key string, value json.RawMessage) (json.RawMessage, time.Time, error)
}

func (f *fakeConfRepo) Get(uzid, key string) (json.RawMessage, time.Time, error) {
	if f.getFn != nil {
		return f.getFn(uzid, key)
	}
	return nil, time.Time{}, repository.ErrUserConfNotFound
}

func (f *fakeConfRepo) Upsert(uzid, key string, value json.RawMessage) (json.RawMessage, time.Time, error) {
	if f.upsertFn != nil {
		return f.upsertFn(uzid, key, value)
	}
	return value, time.Now(), nil
}

type fakeIdentityResolver struct {
	resolveFn func(authUID string) (string, error)
}

func (f *fakeIdentityResolver) ResolveOrCreateUZID(authUID string) (string, error) {
	if f.resolveFn != nil {
		return f.resolveFn(authUID)
	}
	return "uzid-default", nil
}

func executeConfRequestWithUserID(t *testing.T, method, path, body, uid, role, userID string) *httptest.ResponseRecorder {
	t.Helper()

	var reader *strings.Reader
	if body == "" {
		reader = strings.NewReader("")
	} else {
		reader = strings.NewReader(body)
	}

	req := httptest.NewRequest(method, path, reader)
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if userID != "" {
		req.Header.Set("x-user-id", userID)
	}

	w := httptest.NewRecorder()
	r := gin.New()
	r.Use(func(c *gin.Context) {
		if uid != "" {
			c.Set("verified_uid", uid)
		}
		if role != "" {
			c.Set("verified_role", role)
		}
		c.Next()
	})
	r.GET("/api/business/conf/:key", GetConf)
	r.PUT("/api/business/conf/:key", PutConf)
	r.ServeHTTP(w, req)
	return w
}

func executeConfRequest(t *testing.T, method, path, body, uid, role string) *httptest.ResponseRecorder {
	return executeConfRequestWithUserID(t, method, path, body, uid, role, uid)
}

func TestConfHandlers(t *testing.T) {
	gin.SetMode(gin.TestMode)
	originalRepo := confRepo
	originalResolver := confIdentityResolver
	t.Cleanup(func() { confRepo = originalRepo })
	t.Cleanup(func() { confIdentityResolver = originalResolver })

	t.Run("Given missing uid When getting conf Then returns 401", func(t *testing.T) {
		confRepo = &fakeConfRepo{}
		confIdentityResolver = &fakeIdentityResolver{}
		w := executeConfRequest(t, http.MethodGet, "/api/business/conf/website_filters_text", "", "", "user")
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401, got %d", w.Code)
		}
	})

	t.Run("Given missing userId header When getting conf Then returns 403", func(t *testing.T) {
		confRepo = &fakeConfRepo{}
		confIdentityResolver = &fakeIdentityResolver{}
		w := executeConfRequestWithUserID(
			t,
			http.MethodGet,
			"/api/business/conf/website_filters_text",
			"",
			"user-1",
			"user",
			"",
		)
		if w.Code != http.StatusForbidden {
			t.Fatalf("expected 403, got %d", w.Code)
		}
	})

	t.Run("Given missing userId header When putting conf Then returns 403", func(t *testing.T) {
		confRepo = &fakeConfRepo{}
		confIdentityResolver = &fakeIdentityResolver{}
		w := executeConfRequestWithUserID(
			t,
			http.MethodPut,
			"/api/business/conf/website_filters_text",
			`{"value":{"text":"a"}}`,
			"user-1",
			"user",
			"",
		)
		if w.Code != http.StatusForbidden {
			t.Fatalf("expected 403, got %d", w.Code)
		}
	})

	t.Run("Given blank userId header When putting conf Then returns 403", func(t *testing.T) {
		confRepo = &fakeConfRepo{}
		confIdentityResolver = &fakeIdentityResolver{}
		w := executeConfRequestWithUserID(
			t,
			http.MethodPut,
			"/api/business/conf/website_filters_text",
			`{"value":{"text":"a"}}`,
			"user-1",
			"user",
			"   ",
		)
		if w.Code != http.StatusForbidden {
			t.Fatalf("expected 403, got %d", w.Code)
		}
	})

	t.Run("Given mismatched userId header When getting conf Then returns 403", func(t *testing.T) {
		confRepo = &fakeConfRepo{}
		confIdentityResolver = &fakeIdentityResolver{}
		w := executeConfRequestWithUserID(
			t,
			http.MethodGet,
			"/api/business/conf/website_filters_text",
			"",
			"user-1",
			"user",
			"user-2",
		)
		if w.Code != http.StatusForbidden {
			t.Fatalf("expected 403, got %d", w.Code)
		}
	})

	t.Run("Given mismatched userId header When putting conf Then returns 403", func(t *testing.T) {
		confRepo = &fakeConfRepo{}
		confIdentityResolver = &fakeIdentityResolver{}
		w := executeConfRequestWithUserID(
			t,
			http.MethodPut,
			"/api/business/conf/website_filters_text",
			`{"value":{"text":"a"}}`,
			"user-1",
			"user",
			"user-2",
		)
		if w.Code != http.StatusForbidden {
			t.Fatalf("expected 403, got %d", w.Code)
		}
	})

	t.Run("Given invalid key When getting conf Then returns 400", func(t *testing.T) {
		confRepo = &fakeConfRepo{}
		confIdentityResolver = &fakeIdentityResolver{}
		w := executeConfRequest(t, http.MethodGet, "/api/business/conf/invalid%20key", "", "user-1", "user")
		if w.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d", w.Code)
		}
	})

	t.Run("Given conf item missing When getting conf Then returns 404", func(t *testing.T) {
		confIdentityResolver = &fakeIdentityResolver{
			resolveFn: func(authUID string) (string, error) {
				if authUID != "user-1" {
					t.Fatalf("unexpected auth uid: %s", authUID)
				}
				return "uzid-1", nil
			},
		}
		confRepo = &fakeConfRepo{
			getFn: func(uzid, key string) (json.RawMessage, time.Time, error) {
				if uzid != "uzid-1" {
					t.Fatalf("unexpected uzid: %s", uzid)
				}
				return nil, time.Time{}, repository.ErrUserConfNotFound
			},
		}
		w := executeConfRequest(t, http.MethodGet, "/api/business/conf/website_filters_text", "", "user-1", "user")
		if w.Code != http.StatusNotFound {
			t.Fatalf("expected 404, got %d", w.Code)
		}
	})

	t.Run("Given valid conf item When getting conf Then returns value", func(t *testing.T) {
		now := time.Now().UTC()
		confIdentityResolver = &fakeIdentityResolver{
			resolveFn: func(authUID string) (string, error) { return "uzid-1", nil },
		}
		confRepo = &fakeConfRepo{
			getFn: func(uzid, key string) (json.RawMessage, time.Time, error) {
				if uzid != "uzid-1" {
					t.Fatalf("unexpected uzid: %s", uzid)
				}
				return json.RawMessage(`{"text":"example.com##.ad"}`), now, nil
			},
		}
		w := executeConfRequest(t, http.MethodGet, "/api/business/conf/website_filters_text", "", "user-1", "user")
		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d body=%s", w.Code, w.Body.String())
		}

		var resp map[string]interface{}
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatalf("failed to decode response: %v", err)
		}
		value, ok := resp["value"].(map[string]interface{})
		if !ok || value["text"] != "example.com##.ad" {
			t.Fatalf("unexpected response value: %+v", resp["value"])
		}
	})

	t.Run("Given missing value When putting conf Then returns 400", func(t *testing.T) {
		confRepo = &fakeConfRepo{}
		confIdentityResolver = &fakeIdentityResolver{}
		w := executeConfRequest(t, http.MethodPut, "/api/business/conf/website_filters_text", `{}`, "user-1", "user")
		if w.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d", w.Code)
		}
	})

	t.Run("Given repository failure When putting conf Then returns 500", func(t *testing.T) {
		confIdentityResolver = &fakeIdentityResolver{
			resolveFn: func(authUID string) (string, error) { return "uzid-1", nil },
		}
		confRepo = &fakeConfRepo{
			upsertFn: func(uzid, key string, value json.RawMessage) (json.RawMessage, time.Time, error) {
				return nil, time.Time{}, errors.New("db down")
			},
		}
		w := executeConfRequest(t, http.MethodPut, "/api/business/conf/website_filters_text", `{"value":{"text":"abc"}}`, "user-1", "user")
		if w.Code != http.StatusInternalServerError {
			t.Fatalf("expected 500, got %d", w.Code)
		}
	})

	t.Run("Given valid request When putting conf Then returns saved value", func(t *testing.T) {
		now := time.Now().UTC()
		confIdentityResolver = &fakeIdentityResolver{
			resolveFn: func(authUID string) (string, error) { return "uzid-1", nil },
		}
		confRepo = &fakeConfRepo{
			upsertFn: func(uzid, key string, value json.RawMessage) (json.RawMessage, time.Time, error) {
				if uzid != "uzid-1" || key != "website_filters_text" {
					t.Fatalf("unexpected uzid/key: %s/%s", uzid, key)
				}
				return value, now, nil
			},
		}
		w := executeConfRequest(t, http.MethodPut, "/api/business/conf/website_filters_text", `{"value":{"text":"abc"}}`, "user-1", "user")
		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d body=%s", w.Code, w.Body.String())
		}

		var resp map[string]interface{}
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatalf("failed to decode response: %v", err)
		}
		value, ok := resp["value"].(map[string]interface{})
		if !ok || value["text"] != "abc" {
			t.Fatalf("unexpected response value: %+v", resp["value"])
		}
	})

	t.Run("Given resolver failure When getting conf Then returns 500", func(t *testing.T) {
		confIdentityResolver = &fakeIdentityResolver{
			resolveFn: func(authUID string) (string, error) {
				return "", errors.New("resolver down")
			},
		}
		confRepo = &fakeConfRepo{}
		w := executeConfRequest(t, http.MethodGet, "/api/business/conf/website_filters_text", "", "user-1", "user")
		if w.Code != http.StatusInternalServerError {
			t.Fatalf("expected 500, got %d", w.Code)
		}
	})

	t.Run("Given resolver reports unbound identity When putting conf Then returns 403", func(t *testing.T) {
		confIdentityResolver = &fakeIdentityResolver{
			resolveFn: func(authUID string) (string, error) {
				return "", repository.ErrAuthIdentityNotBoundToUser
			},
		}
		confRepo = &fakeConfRepo{}
		w := executeConfRequest(t, http.MethodPut, "/api/business/conf/website_filters_text", `{"value":{"text":"abc"}}`, "local_xxx", "user")
		if w.Code != http.StatusForbidden {
			t.Fatalf("expected 403, got %d", w.Code)
		}
	})

	t.Run("Given guest-like auth uid not bound in users When putting conf Then returns 403", func(t *testing.T) {
		confIdentityResolver = &fakeIdentityResolver{
			resolveFn: func(authUID string) (string, error) {
				return "", repository.ErrAuthIdentityNotBoundToUser
			},
		}
		confRepo = &fakeConfRepo{}
		w := executeConfRequest(t, http.MethodPut, "/api/business/conf/website_filters_text", `{"value":{"text":"a"}}`, "temp-guest-uid", "guest")
		if w.Code != http.StatusForbidden {
			t.Fatalf("expected 403, got %d", w.Code)
		}
	})
}
