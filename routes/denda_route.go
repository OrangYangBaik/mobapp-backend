package routes

import (
	"fiber-mongo-api/controllers"
	"fiber-mongo-api/middlewares"

	"github.com/gofiber/fiber/v2"
)

func DendaRoute(app *fiber.App) {
	app.Post("/addDenda", middlewares.JWTMiddleware(), controllers.CreateDenda)
	app.Post("/deleteDenda", middlewares.JWTMiddleware(), controllers.DeleteADenda)
	app.Post("/payDenda", controllers.PayDenda)
	app.Post("/editDenda/:dendaID/:groupRefKey", middlewares.JWTMiddleware(), controllers.EditADenda)
	app.Get("/allDenda/:memberID/:groupID", controllers.GetAllDenda)
	app.Get("/paidDenda/:memberID/:groupID", controllers.GetPaidDenda)
	app.Get("/unPaidDenda/:memberID/:groupID", controllers.GetUnPaidDenda)
	app.Get("/getDendaSpesific/:dendaID", controllers.GetDenda)
	app.Get("/getDendaNamaTotal/:groupRefKey", controllers.GetDendaNamaTotal)
}
