package audit

import "github.com/gin-gonic/gin"

// Record is a best-effort audit hook. Not security-relevant.
func Record(c *gin.Context) {
	_ = c.Request.URL.Path
}
