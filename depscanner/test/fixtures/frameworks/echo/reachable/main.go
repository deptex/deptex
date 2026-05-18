package main

import (
	"net/http"

	"github.com/labstack/echo/v4"
)

// CVE-2022-40083 — echo <= 4.6.3 open redirect via c.Redirect with
// user-controlled URL.
func main() {
	e := echo.New()
	e.GET("/go", func(c echo.Context) error {
		// Sink: redirect to attacker URL.
		return c.Redirect(http.StatusFound, c.QueryParam("u"))
	})
	_ = e.Start(":8080")
}
