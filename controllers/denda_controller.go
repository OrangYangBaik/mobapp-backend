package controllers

import (
	"context"
	"fiber-mongo-api/configs"
	"fiber-mongo-api/models"
	"fiber-mongo-api/responses"
	"net/http"
	"time"

	"github.com/go-playground/validator/v10"
	"github.com/gofiber/fiber/v2"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

var dendaCollection *mongo.Collection = configs.GetCollection(configs.DB, "dendas")
var dendaValidate = validator.New()

func CreateDenda(c *fiber.Ctx) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var denda models.Denda

	// Validate the request body
	if err := c.BodyParser(&denda); err != nil {
		return c.Status(http.StatusBadRequest).JSON(responses.DendaResponse{
			Status:  http.StatusBadRequest,
			Message: "Failed to parse the request body",
			Data:    &fiber.Map{"error": err.Error()},
		})
	}

	// Use the validator library to validate required fields
	if validationErr := dendaValidate.Struct(&denda); validationErr != nil {
		return c.Status(http.StatusBadRequest).JSON(responses.DendaResponse{
			Status:  http.StatusBadRequest,
			Message: "Validation failed",
			Data:    &fiber.Map{"error": validationErr.Error()},
		})
	}

	// ID_Member primitive.ObjectID `json:"id_member,omitempty" validate:"required"`
	// ID_Group   primitive.ObjectID `json:"id_group,omitempty" validate:"required"`
	// Hari      string             `json:"hari,omitempty" validate:"required"`
	// Nominal   string             `json:"nominal,omitempty" validate:"required"`
	// Desc      string             `json:"desc,omitempty" validate:"required"`

	newDenda := models.Denda{
		ID:        primitive.NewObjectID(),
		ID_Member: denda.ID_Member,
		ID_Group:  denda.ID_Group,
		Hari:      denda.Hari,
		Nominal:   denda.Nominal,
		Desc:      denda.Desc,
	}

	result, err := groupCollection.InsertOne(ctx, newDenda)
	if err != nil {
		// Handle the error more gracefully, perhaps log and return a user-friendly message
		return c.Status(http.StatusInternalServerError).JSON(responses.DendaResponse{
			Status:  http.StatusInternalServerError,
			Message: "Failed to insert group",
			Data:    &fiber.Map{"error": err.Error()},
		})
	}

	return c.Status(http.StatusCreated).JSON(responses.DendaResponse{
		Status:  http.StatusCreated,
		Message: "group created successfully",
		Data:    &fiber.Map{"dendaId": result.InsertedID},
	})
}

func DeleteADenda(c *fiber.Ctx) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	dendaID := c.Params("dendaID")
	defer cancel()

	objId, _ := primitive.ObjectIDFromHex(dendaID)

	result, err := dendaCollection.DeleteOne(ctx, bson.M{"id": objId})
	if err != nil {
		return c.Status(http.StatusInternalServerError).JSON(responses.DendaResponse{Status: http.StatusInternalServerError, Message: "error", Data: &fiber.Map{"data": err.Error()}})
	}

	if result.DeletedCount < 1 {
		return c.Status(http.StatusNotFound).JSON(
			responses.DendaResponse{Status: http.StatusNotFound, Message: "error", Data: &fiber.Map{"data": "Denda with specified ID not found!"}},
		)
	}

	return c.Status(http.StatusOK).JSON(
		responses.DendaResponse{Status: http.StatusOK, Message: "success", Data: &fiber.Map{"data": "Denda successfully deleted!"}},
	)
}

func GetAllDenda(c *fiber.Ctx) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	var members []models.Member
	defer cancel()

	results, err := memberCollection.Find(ctx, bson.M{})

	if err != nil {
		return c.Status(http.StatusInternalServerError).JSON(responses.MemberResponse{Status: http.StatusInternalServerError, Message: "error", Data: &fiber.Map{"data": err.Error()}})
	}

	//reading from the db in an optimal way
	defer results.Close(ctx)
	for results.Next(ctx) {
		var singleMember models.Member
		if err = results.Decode(&singleMember); err != nil {
			return c.Status(http.StatusInternalServerError).JSON(responses.MemberResponse{Status: http.StatusInternalServerError, Message: "error", Data: &fiber.Map{"data": err.Error()}})
		}

		members = append(members, singleMember)
	}

	return c.Status(http.StatusOK).JSON(
		responses.MemberResponse{Status: http.StatusOK, Message: "success", Data: &fiber.Map{"data": members}},
	)
}
