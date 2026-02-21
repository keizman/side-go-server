package api

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/yourname/side-go-server/repository"
)

const maxConfValueBytes = 256 * 1024

var confKeyPattern = regexp.MustCompile(`^[a-z0-9_:-]{1,100}$`)

type userConfRepository interface {
	Get(uzid, key string) (json.RawMessage, time.Time, error)
	Upsert(uzid, key string, value json.RawMessage) (json.RawMessage, time.Time, error)
}

type authIdentityResolver interface {
	ResolveOrCreateUZID(authUID string) (string, error)
}

var confRepo userConfRepository = repository.NewUserConfRepository()
var confIdentityResolver authIdentityResolver = repository.NewAuthIdentityRepository()

type upsertConfRequest struct {
	Value json.RawMessage `json:"value"`
}

func GetConf(c *gin.Context) {
	uid := strings.TrimSpace(c.GetString("verified_uid"))
	role := strings.TrimSpace(c.GetString("verified_role"))
	userID := strings.TrimSpace(c.GetHeader("x-user-id"))
	key := strings.TrimSpace(c.Param("key"))

	if uid == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Not authenticated"})
		return
	}
	if role != "user" && role != "admin" {
		c.JSON(http.StatusForbidden, gin.H{"error": "Cloud sync requires logged-in user"})
		return
	}
	if userID == "" {
		c.JSON(http.StatusForbidden, gin.H{"error": "Cloud sync requires logged-in userId"})
		return
	}
	if userID != uid {
		c.JSON(http.StatusForbidden, gin.H{"error": "Cloud sync userId mismatch"})
		return
	}
	if !confKeyPattern.MatchString(key) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid conf key"})
		return
	}

	uzid, err := confIdentityResolver.ResolveOrCreateUZID(uid)
	if err != nil {
		log.Printf("ERROR conf resolve uzid failed: ip=%s auth_uid=%q key=%q err=%v", c.ClientIP(), uid, key, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to resolve user storage id"})
		return
	}

	raw, updatedAt, err := confRepo.Get(uzid, key)
	if err != nil {
		if errors.Is(err, repository.ErrUserConfNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": "Conf item not found"})
			return
		}
		log.Printf("ERROR conf get failed: ip=%s auth_uid=%q uzid=%q key=%q err=%v", c.ClientIP(), uid, uzid, key, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to read conf item"})
		return
	}

	var value interface{}
	if err := json.Unmarshal(raw, &value); err != nil {
		log.Printf("ERROR conf get decode failed: ip=%s auth_uid=%q uzid=%q key=%q err=%v", c.ClientIP(), uid, uzid, key, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Stored conf data is invalid"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"key":        key,
		"value":      value,
		"updated_at": updatedAt.UTC().Format(time.RFC3339),
	})
}

func PutConf(c *gin.Context) {
	uid := strings.TrimSpace(c.GetString("verified_uid"))
	role := strings.TrimSpace(c.GetString("verified_role"))
	userID := strings.TrimSpace(c.GetHeader("x-user-id"))
	key := strings.TrimSpace(c.Param("key"))

	if uid == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Not authenticated"})
		return
	}
	if role != "user" && role != "admin" {
		c.JSON(http.StatusForbidden, gin.H{"error": "Cloud sync requires logged-in user"})
		return
	}
	if userID == "" {
		c.JSON(http.StatusForbidden, gin.H{"error": "Cloud sync requires logged-in userId"})
		return
	}
	if userID != uid {
		c.JSON(http.StatusForbidden, gin.H{"error": "Cloud sync userId mismatch"})
		return
	}
	if !confKeyPattern.MatchString(key) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid conf key"})
		return
	}

	uzid, err := confIdentityResolver.ResolveOrCreateUZID(uid)
	if err != nil {
		log.Printf("ERROR conf resolve uzid failed: ip=%s auth_uid=%q key=%q err=%v", c.ClientIP(), uid, key, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to resolve user storage id"})
		return
	}

	var req upsertConfRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}
	if len(req.Value) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "value is required"})
		return
	}
	if len(req.Value) > maxConfValueBytes {
		c.JSON(http.StatusRequestEntityTooLarge, gin.H{"error": "value too large"})
		return
	}
	if !json.Valid(req.Value) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "value must be valid JSON"})
		return
	}

	raw, updatedAt, err := confRepo.Upsert(uzid, key, req.Value)
	if err != nil {
		log.Printf("ERROR conf upsert failed: ip=%s auth_uid=%q uzid=%q key=%q err=%v", c.ClientIP(), uid, uzid, key, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save conf item"})
		return
	}

	var value interface{}
	if err := json.Unmarshal(raw, &value); err != nil {
		log.Printf("ERROR conf upsert decode failed: ip=%s auth_uid=%q uzid=%q key=%q err=%v", c.ClientIP(), uid, uzid, key, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Stored conf data is invalid"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"key":        key,
		"value":      value,
		"updated_at": updatedAt.UTC().Format(time.RFC3339),
	})
}
