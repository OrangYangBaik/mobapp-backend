package routes

import (
	"fiber-mongo-api/controllers"

	"github.com/gofiber/fiber/v2"
)

func DendaRoute(app *fiber.App) {
	app.Post("/denda", controllers.CreateDenda)            
	app.Delete("/denda/:dendaID", controllers.DeleteADenda)
	app.Get("/dendas/:memberID/:groupID", controllers.GetAllDenda)
}
