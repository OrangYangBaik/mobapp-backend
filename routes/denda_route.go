package routes

import (
	"fiber-mongo-api/controllers" //add this

	"github.com/gofiber/fiber/v2"
)

func DendaRoute(app *fiber.App) {
	app.Post("/denda", controllers.CreateDenda)             //create
	app.Delete("/denda/:dendaID", controllers.DeleteADenda) //delete
	app.Get("/dendas/:memberID/:groupID", controllers.GetAllDenda)
}
