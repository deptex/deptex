package main

import (
	"net/http"

	"github.com/labstack/echo/v4"
)

// echo handler returns plain JSON. No c.Redirect anywhere.
func main() {
	e := echo.New()
	e.GET("/healthz", func(c echo.Context) error {
		return c.JSON(http.StatusOK, map[string]bool{"ok": true})
	})
	_ = e.Start(":8080")
}
