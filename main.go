package main

import (
	"log"
	"net/http"
	"strings"
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

func logServiceRole(mode, role, port string, endpoints []string) {
	log.Printf(
		"Service startup: mode=%s role=%s port=%s endpoints=%s",
		mode,
		role,
		port,
		strings.Join(endpoints, ", "),
	)
}

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

	gin.SetMode(config.Cfg.GinMode)

	r := gin.Default()

	mode := config.Cfg.ServiceMode
	var role string
	var exposedEndpoints []string

	switch mode {
	case "AUTH":
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

		if err := authHandlers.InitExtensionWhitelist(); err != nil {
			log.Fatalf("Failed to initialize extension whitelist: %v", err)
		}

		r.POST("/auth_token", authHandlers.AuthToken)
		r.GET("/check_token", authHandlers.CheckToken)

		r.POST("/api/register", authHandlersAPI.Register)
		r.Any("/auth/*any", gin.WrapH(http.StripPrefix("/auth", authHandler)))
		role = "auth-gateway"
		exposedEndpoints = []string{
			"POST /auth_token",
			"GET /check_token",
			"POST /api/register",
			"ANY /auth/*",
		}

	case "BUSINESS":
		apiGroup := r.Group("/api")
		apiGroup.Use(middleware.VerifySignature())
		{
			apiGroup.GET("/business/conf/:key", apiHandlers.GetConf)
			apiGroup.PUT("/business/conf/:key", apiHandlers.PutConf)
		}
		role = "business-conf-sync"
		exposedEndpoints = []string{
			"GET /api/business/conf/:key",
			"PUT /api/business/conf/:key",
		}

	default:
		log.Fatalf("SERVICE_MODE must be AUTH or BUSINESS, got: %s", mode)
	}

	logServiceRole(mode, role, config.Cfg.Port, exposedEndpoints)

	if err := r.Run(":" + config.Cfg.Port); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
