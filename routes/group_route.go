package routes

import (
	"fiber-mongo-api/controllers" //add this

	"github.com/gofiber/fiber/v2"
)

func GroupRoute(app *fiber.App) {
	app.Post("/group", controllers.CreateGroup)                 //create
	app.Delete("/group/:groupRefKey", controllers.DeleteAGroup) //delete
	app.Get("/group/:groupRefKey", controllers.GetAGroup)
}
