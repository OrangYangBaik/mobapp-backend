package routes

import (
	"fiber-mongo-api/controllers" //add this
	"fiber-mongo-api/middlewares"

	"github.com/gofiber/fiber/v2"
)

func GroupRoute(app *fiber.App) {
	app.Get("/group/:groupRefKey", controllers.GetAGroup)
	app.Post("/group", middlewares.JWTMiddleware(), controllers.CreateGroup)                    //create
	app.Delete("/group/delete/:groupID", middlewares.JWTMiddleware(), controllers.DeleteAGroup) //delete
	app.Post("/group/join/:groupID", middlewares.JWTMiddleware(), controllers.JoinGroup)
}
