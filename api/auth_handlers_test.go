package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/yourname/side-go-server/models"
)

type fakeAuthRepo struct {
	getUserByUsernameFn func(username string) (*models.User, error)
	getUserByEmailFn    func(email string) (*models.User, error)
	createUserFn        func(user *models.User, password string) error
}

func (f *fakeAuthRepo) GetUserByUsername(username string) (*models.User, error) {
	if f.getUserByUsernameFn != nil {
		return f.getUserByUsernameFn(username)
	}
	return nil, errors.New("not implemented")
}

func (f *fakeAuthRepo) GetUserByEmail(email string) (*models.User, error) {
	if f.getUserByEmailFn != nil {
		return f.getUserByEmailFn(email)
	}
	return nil, errors.New("not implemented")
}

func (f *fakeAuthRepo) CreateUser(user *models.User, password string) error {
	if f.createUserFn != nil {
		return f.createUserFn(user, password)
	}
	return errors.New("not implemented")
}

func executeRegister(handler *AuthHandlers, body string) *httptest.ResponseRecorder {
	r := gin.New()
	r.POST("/api/register", handler.Register)

	req := httptest.NewRequest(http.MethodPost, "/api/register", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "203.0.113.7:12345"

	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func TestRegister(t *testing.T) {
	gin.SetMode(gin.TestMode)

	t.Run("Given malformed JSON When register called Then responds 400", func(t *testing.T) {
		h := &AuthHandlers{userRepo: &fakeAuthRepo{}}
		w := executeRegister(h, `{"username":"u1"`)

		if w.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d", w.Code)
		}
	})

	t.Run("Given invalid email format When register called Then responds 400", func(t *testing.T) {
		h := &AuthHandlers{userRepo: &fakeAuthRepo{}}
		w := executeRegister(h, `{"username":"new_user","email":"invalid","password":"password1","confirm_password":"password1"}`)

		if w.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d", w.Code)
		}
	})

	t.Run("Given username already exists When register called Then responds 409", func(t *testing.T) {
		h := &AuthHandlers{userRepo: &fakeAuthRepo{
			getUserByUsernameFn: func(username string) (*models.User, error) {
				return &models.User{ID: 1, Username: username}, nil
			},
		}}
		w := executeRegister(h, `{"username":"new_user","email":"new@example.com","password":"password1","confirm_password":"password1"}`)

		if w.Code != http.StatusConflict {
			t.Fatalf("expected 409, got %d", w.Code)
		}
	})

	t.Run("Given email already exists When register called Then responds 409", func(t *testing.T) {
		h := &AuthHandlers{userRepo: &fakeAuthRepo{
			getUserByUsernameFn: func(username string) (*models.User, error) {
				return nil, errors.New("not found")
			},
			getUserByEmailFn: func(email string) (*models.User, error) {
				return &models.User{ID: 2, Email: email}, nil
			},
		}}
		w := executeRegister(h, `{"username":"new_user","email":"new@example.com","password":"password1","confirm_password":"password1"}`)

		if w.Code != http.StatusConflict {
			t.Fatalf("expected 409, got %d", w.Code)
		}
	})

	t.Run("Given repository fails creating user When register called Then responds 500", func(t *testing.T) {
		h := &AuthHandlers{userRepo: &fakeAuthRepo{
			getUserByUsernameFn: func(username string) (*models.User, error) {
				return nil, errors.New("not found")
			},
			getUserByEmailFn: func(email string) (*models.User, error) {
				return nil, errors.New("not found")
			},
			createUserFn: func(user *models.User, password string) error {
				return errors.New("insert failed")
			},
		}}
		w := executeRegister(h, `{"username":"new_user","email":"new@example.com","password":"password1","confirm_password":"password1"}`)

		if w.Code != http.StatusInternalServerError {
			t.Fatalf("expected 500, got %d", w.Code)
		}
	})

	t.Run("Given valid input with extra spaces When register called Then trims and creates active user", func(t *testing.T) {
		called := false
		h := &AuthHandlers{userRepo: &fakeAuthRepo{
			getUserByUsernameFn: func(username string) (*models.User, error) {
				if username != "new_user" {
					t.Fatalf("expected trimmed username, got %q", username)
				}
				return nil, errors.New("not found")
			},
			getUserByEmailFn: func(email string) (*models.User, error) {
				if email != "new@example.com" {
					t.Fatalf("expected trimmed email, got %q", email)
				}
				return nil, errors.New("not found")
			},
			createUserFn: func(user *models.User, password string) error {
				called = true
				if user.Username != "new_user" || user.Email != "new@example.com" {
					t.Fatalf("unexpected user identity: %+v", user)
				}
				if user.Role != "user" || user.Status != "active" {
					t.Fatalf("unexpected defaults: role=%s status=%s", user.Role, user.Status)
				}
				if !user.DisplayName.Valid || user.DisplayName.String != "new_user" {
					t.Fatalf("expected display name new_user, got %+v", user.DisplayName)
				}
				if !user.RegisterIP.Valid || user.RegisterIP.String == "" {
					t.Fatalf("expected register IP to be set, got %+v", user.RegisterIP)
				}
				if password != "password1" {
					t.Fatalf("unexpected password value")
				}
				user.ID = 88
				return nil
			},
		}}

		w := executeRegister(h, `{"username":"  new_user ","email":"  new@example.com  ","password":"password1","confirm_password":"password1"}`)

		if w.Code != http.StatusCreated {
			t.Fatalf("expected 201, got %d, body=%s", w.Code, w.Body.String())
		}
		if !called {
			t.Fatalf("expected create user to be called")
		}

		var resp map[string]interface{}
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatalf("failed to parse response: %v", err)
		}
		if resp["user_id"].(float64) != 88 {
			t.Fatalf("expected user_id 88, got %v", resp["user_id"])
		}
	})
}
