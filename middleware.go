package main

import (
	"errors"
	"github.com/gin-gonic/gin"
)

func ErrorHandlerMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Next()
		for _, err := range c.Errors {
			var (
				validationError *ValidationError
			)

			switch {
			case errors.As(err.Err, &validationError):
				resJSON := map[string]any{
					"msg":   validationError.Message,
					"error": validationError.ErrorMessage,
				}
				c.AbortWithStatusJSON(validationError.StatusCode, resJSON)
			default:
				c.AbortWithStatus(500)
				return
			}
		}
	}
}

func CORSMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		origin := c.Request.Header.Get("Origin")

		// Allow requests from any origin during development
		// In production, you might want to restrict this to specific origins
		c.Writer.Header().Set("Access-Control-Allow-Origin", origin)

		c.Writer.Header().Set("Access-Control-Allow-Credentials", "true")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, accept, origin, Cache-Control, X-Requested-With, ngrok-skip-browser-warning")
		c.Writer.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")

		// Handle preflight requests
		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}

		c.Next()
	}
}
