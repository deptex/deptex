package audit

import "github.com/gin-gonic/gin"

func Record(c *gin.Context) {
	_ = c.Request.URL.Path
}
