package main

import (
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-pkgz/auth"
	"github.com/go-pkgz/auth/avatar"
	"github.com/go-pkgz/auth/provider"
	"github.com/go-pkgz/auth/token"
	apiHandlers "github.com/yourname/side-go-server/api"
	authHandlers "github.com/yourname/side-go-server/auth"
	"github.com/yourname/side-go-server/config"
	"github.com/yourname/side-go-server/internal/database"
	"github.com/yourname/side-go-server/internal/redis"
	"github.com/yourname/side-go-server/middleware"
	"github.com/yourname/side-go-server/repository"
)

func main() {
	if err := config.Load(); err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	if err := database.InitDB(
		config.Cfg.DatabaseURL,
		config.Cfg.DatabaseMaxOpenConns,
		config.Cfg.DatabaseMaxIdleConns,
		config.Cfg.DatabaseConnMaxLifetime,
	); err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}
	defer database.Close()

	if err := redis.InitRedis(); err != nil {
		log.Fatalf("Failed to initialize Redis: %v", err)
	}
	defer redis.Close()

	userRepo := repository.NewUserRepository()
	if err := userRepo.CreateDefaultAdmin(
		config.Cfg.AdminUsername,
		config.Cfg.AdminPassword,
		config.Cfg.AdminEmail,
	); err != nil {
		log.Fatalf("Failed to create default admin: %v", err)
	}

	authService := auth.NewService(auth.Opts{
		SecretReader: token.SecretFunc(func(id string) (string, error) {
			return config.Cfg.JWTSecret, nil
		}),
		TokenDuration:  time.Duration(config.Cfg.TokenDuration) * time.Second,
		CookieDuration: time.Duration(config.Cfg.CookieDuration) * time.Second,
		Issuer:         config.Cfg.JWTIssuer,
		URL:            "http://localhost:" + config.Cfg.Port,
		AvatarStore:    avatar.NewNoOp(),
	})

	authService.AddDirectProvider("local", provider.CredCheckerFunc(func(user, password string) (ok bool, err error) {
		existingUser, err := userRepo.GetUserByUsernameOrEmail(user)
		if err != nil {
			return false, nil
		}

		if existingUser.Status != "active" {
			return false, nil
		}

		if err := userRepo.VerifyPassword(existingUser.PasswordHash, password); err != nil {
			return false, nil
		}

		return true, nil
	}))

	authHandler, _ := authService.Handlers()

	authHandlersAPI := apiHandlers.NewAuthHandlers(userRepo)

	gin.SetMode(config.Cfg.GinMode)

	r := gin.Default()

	mode := config.Cfg.ServiceMode
	fmt.Printf("🚀 Starting server in %s mode on port %s\n", mode, config.Cfg.Port)

	switch mode {
	case "AUTH":
		r.POST("/auth_token", authHandlers.AuthToken)
		r.GET("/check_token", authHandlers.CheckToken)

		r.POST("/api/register", authHandlersAPI.Register)
		r.Any("/auth/*any", gin.WrapH(http.StripPrefix("/auth", authHandler)))

	case "BUSINESS":
		apiGroup := r.Group("/api")
		apiGroup.Use(middleware.VerifySignature())
		{
			apiGroup.POST("/login", apiHandlers.Login)
			apiGroup.POST("/logout", apiHandlers.Logout)
			apiGroup.POST("/logout_all", apiHandlers.LogoutAllDevices)
			apiGroup.POST("/translate", apiHandlers.Translate)
			apiGroup.GET("/user/profile", apiHandlers.GetProfile)
		}

	default:
		log.Fatalf("SERVICE_MODE must be AUTH or BUSINESS, got: %s", mode)
	}

	if err := r.Run(":" + config.Cfg.Port); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
