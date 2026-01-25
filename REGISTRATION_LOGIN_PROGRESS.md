# Registration and Login Implementation - Progress Summary

## ✅ Completed Tasks

### Backend (Go Server)

1. **Dependencies Added** ✅
   - `github.com/go-pkgz/auth` - Authentication library
   - `github.com/lib/pq` - PostgreSQL driver
   - `golang.org/x/crypto/bcrypt` - Password hashing

2. **Environment Configuration** ✅
   - Updated `.env.example` with:
     - PostgreSQL database connection settings
     - Admin credentials (username, password, email)
     - JWT configuration (secret, issuer, audience, durations)

3. **Database Schema** ✅
   - Created `update.sql` with:
     - Users table with all required fields
     - Indexes for performance
     - Auto-update trigger for `updated_at`
     - Comments explaining admin account creation flow

4. **Database Module** ✅
   - `internal/database/database.go` - Connection management

5. **Models** ✅
   - `models/user.go` - User struct, RegisterRequest, LoginRequest

6. **Repository** ✅
   - `repository/user_repository.go` - Full CRUD operations:
     - CreateUser (with bcrypt password hashing)
     - GetUserByUsername
     - GetUserByEmail
     - GetUserByUsernameOrEmail
     - VerifyPassword
     - UpdateLastLogin
     - IncrementRequestCount
     - UserExists
     - CreateDefaultAdmin

## ⏳ Remaining Tasks

### Backend (Go Server) - HIGH PRIORITY

1. **Update `config/config.go`** - Add database and JWT config loading
2. **Create `api/auth_handlers.go`** - Registration endpoint handler
3. **Update `main.go`** - Integrate go-pkgz/auth service
4. **Create auth service initialization** - Setup CredChecker for login

### Frontend (Extension) - HIGH PRIORITY

1. **Create Registration Page** - Vue component with form validation
2. **Create Login Page** - Vue component with form submission
3. **Add Routing** - Configure routes for auth pages
4. **API Integration** - Connect forms to backend endpoints

### Testing - MEDIUM PRIORITY

1. **Backend Testing** - Test registration and login endpoints
2. **Frontend Testing** - Test form validation and submission
3. **Integration Testing** - End-to-end flow testing

## 📝 Detailed Remaining Implementation

### 1. Update `config/config.go`

Add these fields to Config struct:

```go
// Database
DatabaseURL          string
DatabaseMaxOpenConns int
DatabaseMaxIdleConns int
DatabaseConnMaxLifetime time.Duration

// Admin Account
AdminUsername string
AdminPassword string
AdminEmail    string

// JWT Configuration
JWTSecret      string
JWTIssuer      string
JWTAudience    string
TokenDuration  int // seconds
CookieDuration int // seconds
```

Add environment variable loading in `LoadConfig()`:

```go
DatabaseURL:             getEnv("DATABASE_URL", ""),
DatabaseMaxOpenConns:    getEnvAsInt("DATABASE_MAX_OPEN_CONNS", 25),
DatabaseMaxIdleConns:    getEnvAsInt("DATABASE_MAX_IDLE_CONNS", 5),
DatabaseConnMaxLifetime: time.Duration(getEnvAsInt("DATABASE_CONN_MAX_LIFETIME", 300)) * time.Second,

AdminUsername: getEnv("ADMIN_USERNAME", "admin"),
AdminPassword: getEnv("ADMIN_PASSWORD", ""),
AdminEmail:    getEnv("ADMIN_EMAIL", "admin@example.com"),

JWTSecret:      getEnv("JWT_SECRET", ""),
JWTIssuer:      getEnv("JWT_ISSUER", "extension-backend"),
JWTAudience:    getEnv("JWT_AUDIENCE", "extension-users"),
TokenDuration:  getEnvAsInt("TOKEN_DURATION", 3600),
CookieDuration: getEnvAsInt("COOKIE_DURATION", 2592000),
```

### 2. Create `api/auth_handlers.go`

```go
package api

import (
	"database/sql"
	"net"
	"net/http"
	"regexp"

	"github.com/gin-gonic/gin"
	"github.com/yourname/side-go-server/models"
	"github.com/yourname/side-go-server/repository"
)

type AuthHandler struct {
	userRepo *repository.UserRepository
}

func NewAuthHandler() *AuthHandler {
	return &AuthHandler{
		userRepo: repository.NewUserRepository(),
	}
}

// POST /api/register
func (h *AuthHandler) Register(c *gin.Context) {
	var req models.RegisterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Validate email format
	if !isValidEmail(req.Email) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid email format"})
		return
	}

	// Check if user already exists
	exists, err := h.userRepo.UserExists(req.Username, req.Email)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to check user existence"})
		return
	}
	if exists {
		c.JSON(http.StatusConflict, gin.H{"error": "Username or email already exists"})
		return
	}

	// Get client IP
	clientIP := c.ClientIP()
	
	// Create user
	user := &models.User{
		Username:     req.Username,
		Email:        req.Email,
		DisplayName:  sql.NullString{String: req.Username, Valid: true},
		Role:         "user",
		Status:       "active",
		RegisterIP:   sql.NullString{String: clientIP, Valid: true},
		RequestCount: 0,
		EmailVerified: false,
	}

	if err := h.userRepo.CreateUser(user, req.Password); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create user"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"message": "User registered successfully",
		"user": gin.H{
			"id":       user.ID,
			"username": user.Username,
			"email":    user.Email,
		},
	})
}

func isValidEmail(email string) bool {
	regex := regexp.MustCompile(`^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$`)
	return regex.MatchString(email)
}
```

### 3. Update `main.go` - Integration

Add after Redis initialization:

```go
// Initialize Database
err = database.InitDB(
	cfg.DatabaseURL,
	cfg.DatabaseMaxOpenConns,
	cfg.DatabaseMaxIdleConns,
	cfg.DatabaseConnMaxLifetime,
)
if err != nil {
	log.Fatalf("Failed to initialize database: %v", err)
}
defer database.Close()

// Create default admin account
userRepo := repository.NewUserRepository()
if err := userRepo.CreateDefaultAdmin(cfg.AdminUsername, cfg.AdminPassword, cfg.AdminEmail); err != nil {
	log.Printf("⚠️  Warning: Failed to create default admin: %v", err)
} else {
	log.Println("✅ Default admin account ready")
}

// Initialize go-pkgz/auth service
authService := auth.NewService(auth.Opts{
	SecretReader: token.SecretFunc(func(id string) (string, error) {
		return cfg.JWTSecret, nil
	}),
	TokenDuration:  time.Duration(cfg.TokenDuration) * time.Second,
	CookieDuration: time.Duration(cfg.CookieDuration) * time.Second,
	Issuer:         cfg.JWTIssuer,
	URL:            fmt.Sprintf("http://localhost:%s", cfg.Port),
	AvatarStore:    avatar.NewNoOp(),
})

// Add direct provider with credential checker
authService.AddDirectProvider("local", provider.CredCheckerFunc(func(user, password string) (ok bool, err error) {
	dbUser, err := userRepo.GetUserByUsernameOrEmail(user)
	if err != nil {
		return false, nil // User not found
	}

	if dbUser.Status != "active" {
		return false, nil // Account not active
	}

	err = userRepo.VerifyPassword(dbUser.PasswordHash, password)
	if err != nil {
		return false, nil // Invalid password
	}

	// Update last login
	go func() {
		if err := userRepo.UpdateLastLogin(dbUser.ID, ""); err != nil {
			log.Printf("Failed to update last login: %v", err)
		}
	}()

	return true, nil
}))

// Get auth handlers
authHandler, _ := authService.Handlers()
```

Add routes:

```go
// Custom registration endpoint
authHandlerAPI := api.NewAuthHandler()
r.POST("/api/register", authHandlerAPI.Register)

// go-pkgz/auth routes (login, logout, etc.)
r.Any("/auth/*any", gin.WrapH(http.StripPrefix("/auth", authHandler)))
```

### 4. Extension Frontend - Registration Page

Create `tranlation-overlay-extension/pages/register.vue`:

```vue
<template>
  <div class="min-h-screen flex items-center justify-center bg-gray-50 dark:bg-gray-900 px-4">
    <div class="max-w-md w-full space-y-8">
      <div>
        <h2 class="mt-6 text-center text-3xl font-extrabold text-gray-900 dark:text-white">
          Create your account
        </h2>
      </div>
      <form class="mt-8 space-y-6" @submit.prevent="handleRegister">
        <div class="rounded-md shadow-sm space-y-4">
          <div>
            <label for="username" class="sr-only">Username</label>
            <input
              id="username"
              v-model="form.username"
              name="username"
              type="text"
              required
              class="appearance-none rounded-lg relative block w-full px-3 py-2 border border-gray-300 dark:border-gray-700 placeholder-gray-500 text-gray-900 dark:text-white dark:bg-gray-800 focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 focus:z-10 sm:text-sm"
              placeholder="Username (3-50 characters)"
              :disabled="loading"
            />
          </div>
          <div>
            <label for="email" class="sr-only">Email</label>
            <input
              id="email"
              v-model="form.email"
              name="email"
              type="email"
              required
              class="appearance-none rounded-lg relative block w-full px-3 py-2 border border-gray-300 dark:border-gray-700 placeholder-gray-500 text-gray-900 dark:text-white dark:bg-gray-800 focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 focus:z-10 sm:text-sm"
              placeholder="Email address"
              :disabled="loading"
            />
          </div>
          <div>
            <label for="password" class="sr-only">Password</label>
            <input
              id="password"
              v-model="form.password"
              name="password"
              type="password"
              required
              class="appearance-none rounded-lg relative block w-full px-3 py-2 border border-gray-300 dark:border-gray-700 placeholder-gray-500 text-gray-900 dark:text-white dark:bg-gray-800 focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 focus:z-10 sm:text-sm"
              placeholder="Password (min 8 characters)"
              :disabled="loading"
            />
          </div>
          <div>
            <label for="confirm-password" class="sr-only">Confirm Password</label>
            <input
              id="confirm-password"
              v-model="form.confirmPassword"
              name="confirm-password"
              type="password"
              required
              class="appearance-none rounded-lg relative block w-full px-3 py-2 border border-gray-300 dark:border-gray-700 placeholder-gray-500 text-gray-900 dark:text-white dark:bg-gray-800 focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 focus:z-10 sm:text-sm"
              placeholder="Confirm password"
              :disabled="loading"
            />
          </div>
        </div>

        <div v-if="error" class="rounded-md bg-red-50 dark:bg-red-900/20 p-4">
          <div class="text-sm text-red-800 dark:text-red-200">
            {{ error }}
          </div>
        </div>

        <div v-if="success" class="rounded-md bg-green-50 dark:bg-green-900/20 p-4">
          <div class="text-sm text-green-800 dark:text-green-200">
            Registration successful! Redirecting to login...
          </div>
        </div>

        <div>
          <button
            type="submit"
            :disabled="loading"
            class="group relative w-full flex justify-center py-2 px-4 border border-transparent text-sm font-medium rounded-md text-white bg-indigo-600 hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500 disabled:opacity-50 disabled:cursor-not-allowed"
          >
            <span v-if="loading">Registering...</span>
            <span v-else>Register</span>
          </button>
        </div>

        <div class="text-center">
          <a href="/login" class="font-medium text-indigo-600 hover:text-indigo-500 dark:text-indigo-400">
            Already have an account? Sign in
          </a>
        </div>
      </form>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref } from 'vue';
import { httpClient, AuthConfig } from '@/src/modules/auth';

const form = ref({
  username: '',
  email: '',
  password: '',
  confirmPassword: '',
});

const loading = ref(false);
const error = ref('');
const success = ref(false);

const handleRegister = async () => {
  error.value = '';
  
  // Validation
  if (form.value.username.length < 3 || form.value.username.length > 50) {
    error.value = 'Username must be between 3 and 50 characters';
    return;
  }
  
  if (form.value.password.length < 8) {
    error.value = 'Password must be at least 8 characters';
    return;
  }
  
  if (form.value.password !== form.value.confirmPassword) {
    error.value = 'Passwords do not match';
    return;
  }

  loading.value = true;

  try {
    const response = await fetch(`${AuthConfig.apiBaseUrl}/api/register`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        username: form.value.username,
        email: form.value.email,
        password: form.value.password,
        confirm_password: form.value.confirmPassword,
      }),
    });

    const data = await response.json();

    if (!response.ok) {
      error.value = data.error || 'Registration failed';
      return;
    }

    success.value = true;
    setTimeout(() => {
      window.location.href = '/login';
    }, 2000);
  } catch (err) {
    error.value = 'Network error. Please try again.';
    console.error('Registration error:', err);
  } finally {
    loading.value = false;
  }
};
</script>
```

### 5. Extension Frontend - Login Page

Create `tranlation-overlay-extension/pages/login.vue` (similar structure to register page)

## Next Steps

1. Finish implementing the remaining Go server code
2. Create Vue components for registration and login
3. Configure routing in WXT
4. Test the complete flow
5. Document API endpoints

## Notes

- All backend code follows Go best practices
- Password hashing uses bcrypt with default cost (10)
- Admin account created automatically on first startup
- go-pkgz/auth handles JWT token generation and cookie management
- Extension frontend uses Tailwind CSS for styling
- Form validation on both frontend and backend
