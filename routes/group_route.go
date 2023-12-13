package routes

import (
	"fiber-mongo-api/controllers" //add this
	"fiber-mongo-api/middlewares"

	"github.com/gofiber/fiber/v2"
)

func GroupRoute(app *fiber.App) {
	app.Get("/group/:groupRefKey", controllers.GetAGroup)
	app.Post("/group", middlewares.JWTMiddleware(), controllers.CreateGroup)
	app.Delete("/group/deactivate/:groupRefKey", middlewares.JWTMiddleware(), controllers.DeactivateAGroup)
	app.Put("/group/activate/:groupRefKey", middlewares.JWTMiddleware(), controllers.ActivateAGroup)
	app.Post("/group/join/:groupRefKey", middlewares.JWTMiddleware(), controllers.JoinGroup)
	app.Get("/allJoinedGroup", middlewares.JWTMiddleware(), controllers.GetAllJoinedGroup)
}
