package main

import (
	"fiber-mongo-api/configs"
	"fiber-mongo-api/routes" //add this

	"github.com/gofiber/fiber/v2"
)

func main() {
	app := fiber.New()

	//run database
	configs.ConnectDB()

	//routes
	app.Get("/", func(c *fiber.Ctx) error {
		return c.SendString("Hello. world")
	})
	routes.MemberRoute(app)
	routes.GroupRoute(app)
	routes.DendaRoute(app)

	app.Listen("0.0.0.0:6000")
}
