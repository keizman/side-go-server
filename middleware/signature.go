package middleware

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"io"
	"net/url"
	"sort"
	"strings"

	"github.com/gin-gonic/gin"
)

func VerifySignature() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if !strings.HasPrefix(authHeader, "Bearer ") {
			c.AbortWithStatusJSON(401, gin.H{"error": "Invalid authorization header"})
			return
		}
		token := strings.TrimPrefix(authHeader, "Bearer ")

		timestamp := c.GetHeader("x-timestamp")
		tempID := c.GetHeader("x-temp-id")
		clientSign := c.GetHeader("x-sign")

		if timestamp == "" || tempID == "" || clientSign == "" {
			c.AbortWithStatusJSON(400, gin.H{"error": "Missing required headers"})
			return
		}

		var payload string

		if c.Request.Method == "GET" {
			sortedQuery := sortQueryString(c.Request.URL.Query())
			payload = fmt.Sprintf("%s|%s|%s", sortedQuery, timestamp, tempID)
		} else {
			bodyBytes, err := io.ReadAll(c.Request.Body)
			if err != nil {
				c.AbortWithStatusJSON(400, gin.H{"error": "Failed to read request body"})
				return
			}
			c.Request.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))

			bodyHash := sha256Hex(bodyBytes)
			payload = fmt.Sprintf("%s|%s|%s", bodyHash, timestamp, tempID)
		}

		serverSign := hmacSHA256(payload, token)

		if !hmac.Equal([]byte(serverSign), []byte(clientSign)) {
			c.AbortWithStatusJSON(403, gin.H{"error": "Signature verification failed"})
			return
		}

		c.Set("verified_uid", c.GetHeader("X-Verified-UID"))
		c.Set("verified_role", c.GetHeader("X-Verified-Role"))
		c.Set("verified_tier", c.GetHeader("X-Verified-Tier"))
		c.Set("verified_device_id", c.GetHeader("X-Verified-DeviceID"))

		c.Next()
	}
}

func sortQueryString(query url.Values) string {
	if len(query) == 0 {
		return ""
	}

	keys := make([]string, 0, len(query))
	for k := range query {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var pairs []string
	for _, k := range keys {
		values := query[k]
		sort.Strings(values)
		for _, v := range values {
			pairs = append(pairs, fmt.Sprintf("%s=%s", k, v))
		}
	}
	return strings.Join(pairs, "&")
}

func sha256Hex(data []byte) string {
	h := sha256.New()
	h.Write(data)
	return fmt.Sprintf("%x", h.Sum(nil))
}

func hmacSHA256(data, key string) string {
	h := hmac.New(sha256.New, []byte(key))
	h.Write([]byte(data))
	return fmt.Sprintf("%x", h.Sum(nil))
}
