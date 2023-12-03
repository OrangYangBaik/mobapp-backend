package routes

import (
	"fiber-mongo-api/controllers" //add this

	"github.com/gofiber/fiber/v2"
)

func MemberRoute(app *fiber.App) {
	app.Post("/member", controllers.CreateMember)              //create
	app.Delete("/member/:memberID", controllers.DeleteAMember) //delete
	app.Put("/member/:memberID", controllers.EditAMember)      //update
	app.Get("/members", controllers.GetAllMember)              //read
	app.Get("/member/:memberID", controllers.GetAMember)
}
