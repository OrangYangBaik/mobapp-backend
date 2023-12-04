package main

import (
	"fiber-mongo-api/configs"
	"fiber-mongo-api/routes" //add this
	"log"
	"os"

	"github.com/gofiber/fiber/v2"
)

func main() {
	app := fiber.New()

	port := os.Getenv("PORT")
	if port == "" {
		port = "6000"
	}

	//run database
	configs.ConnectDB()

	//routes
	routes.MemberRoute(app)
	routes.GroupRoute(app)
	routes.DendaRoute(app)

	log.Fatal(app.Listen("0.0.0.0:" + port))
}
