package main

import (
	"github.com/gofiber/fiber/v2"
)

// CVE-2023-45141 — fiber <= 2.49.0 header injection / open redirect via
// Redirect with user-controlled URL.
func main() {
	app := fiber.New()
	app.Get("/go", func(c *fiber.Ctx) error {
		// Sink: open redirect to attacker URL.
		return c.Redirect(c.Query("u"))
	})
	_ = app.Listen(":3000")
}
