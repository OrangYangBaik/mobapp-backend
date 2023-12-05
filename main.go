package main

import (
	"fiber-mongo-api/configs"
	"fiber-mongo-api/routes"
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

	//buat konfigurasi koneksi ke database
	configs.ConnectDB()

	//router
	routes.MemberRoute(app)
	routes.GroupRoute(app)
	routes.DendaRoute(app)

	log.Fatal(app.Listen("0.0.0.0:" + port))
}
