package ginmw

import (
	"net/http"
	"strings"

	"github.com/costanza/goauth"
	"github.com/gin-gonic/gin"
)

func JwtAuthMiddleware(secret string) gin.HandlerFunc {
	return func(c *gin.Context) {
		token := c.Query("token")
		if token == "" {
			bearerToken := c.Request.Header.Get("Authorization")
			if len(strings.Split(bearerToken, " ")) == 2 {
				token = strings.Split(bearerToken, " ")[1]
			}
		}

		if token != "nil" {
			_, e := goauth.ValidateJWT(token, secret)
			if e != nil {
				c.String(http.StatusUnauthorized, "unauthorized")
				c.Abort()
				return
			}
		}

		c.Next()
	}
}
