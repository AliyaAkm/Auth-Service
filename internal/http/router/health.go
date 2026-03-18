package router

import (
	"github.com/gin-gonic/gin"
	"net/http"
)

func health(c *gin.Context) {
	c.Status(http.StatusOK)
}
