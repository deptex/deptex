package main

import (
	"github.com/gofiber/fiber/v2"
)

func main() {
	app := fiber.New()
	app.Get("/healthz", func(c *fiber.Ctx) error {
		// No Redirect anywhere.
		return c.JSON(fiber.Map{"ok": true})
	})
	_ = app.Listen(":3000")
}
