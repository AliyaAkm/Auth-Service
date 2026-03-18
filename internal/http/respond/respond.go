package respond

import "github.com/gin-gonic/gin"

func JSON(c *gin.Context, status int, v any) {
	c.JSON(status, v)
}

// todo error struct code message

func Error(c *gin.Context, status int, code, message string) {
	c.JSON(status, gin.H{
		"error": gin.H{
			"code":    code,
			"message": message,
		},
	})
}
