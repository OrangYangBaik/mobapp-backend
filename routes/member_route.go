package routes

import (
	"fiber-mongo-api/controllers"
	"fiber-mongo-api/middlewares"

	"github.com/gofiber/fiber/v2"
)

func MemberRoute(app *fiber.App) {
	app.Post("/member", controllers.CreateMember)
	app.Post("/member/login", controllers.LoginMember)
	app.Get("/member/:memberID", controllers.GetAMember)
	app.Get("/semuaMember", controllers.SemuaMember)

	member := app.Group("/members", middlewares.JWTMiddleware())
	member.Get("/:memberID/:groupRefKey", controllers.GetAMember)
	member.Get("/:groupRefKey", controllers.GetAllMember)
	member.Delete("/kickAMember", controllers.KickAMember)
	member.Delete("/:memberID", controllers.DeleteAMember)
	member.Put("/edit/giveAdmin", controllers.GiveAdmin)
	member.Put("/edit/revokeAdmin", controllers.RevokeAdmin)
	member.Put("/edit/:memberID", controllers.EditAMember)
}
