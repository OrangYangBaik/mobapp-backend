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

	// mengambil env variable PORT
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

	// akses server side melalui IP dan port yang ditentukan (pada railway)
	log.Fatal(app.Listen("0.0.0.0:" + port))
}
