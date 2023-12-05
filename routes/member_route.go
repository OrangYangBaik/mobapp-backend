package routes

import (
	"fiber-mongo-api/controllers"
	"fiber-mongo-api/middlewares"

	"github.com/gofiber/fiber/v2"
)

func MemberRoute(app *fiber.App) {
	app.Post("/member", controllers.CreateMember)
	app.Post("/member/login", controllers.LoginMember)
	app.Get("/members", controllers.GetAllMember)
	app.Get("/member/:memberID", controllers.GetAMember)

	member := app.Group("/members", middlewares.JWTMiddleware())
	member.Delete("/:memberID", controllers.DeleteAMember)
	member.Put("/:memberID", controllers.EditAMember)
}
