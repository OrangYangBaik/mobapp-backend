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

var groupCollection *mongo.Collection = configs.GetCollection(configs.DB, "groups")
var groupValidate = validator.New()

func CreateGroup(c *fiber.Ctx) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var group models.Group

	// Validate the request body
	if err := c.BodyParser(&group); err != nil {
		return c.Status(http.StatusBadRequest).JSON(responses.GroupResponse{
			Status:  http.StatusBadRequest,
			Message: "Failed to parse the request body",
			Data:    &fiber.Map{"error": err.Error()},
		})
	}

	// Use the validator library to validate required fields
	if validationErr := groupValidate.Struct(&group); validationErr != nil {
		return c.Status(http.StatusBadRequest).JSON(responses.GroupResponse{
			Status:  http.StatusBadRequest,
			Message: "Validation failed",
			Data:    &fiber.Map{"error": validationErr.Error()},
		})
	}

	newGroup := models.Group{
		ID:        primitive.NewObjectID(),
		NamaGroup: group.NamaGroup,
		RefKey:    group.RefKey,
	}

	result, err := groupCollection.InsertOne(ctx, newGroup)
	if err != nil {
		// Handle the error more gracefully, perhaps log and return a user-friendly message
		return c.Status(http.StatusInternalServerError).JSON(responses.GroupResponse{
			Status:  http.StatusInternalServerError,
			Message: "Failed to insert group",
			Data:    &fiber.Map{"error": err.Error()},
		})
	}

	return c.Status(http.StatusCreated).JSON(responses.GroupResponse{
		Status:  http.StatusCreated,
		Message: "group created successfully",
		Data:    &fiber.Map{"groupId": result.InsertedID},
	})
}

func GetAGroup(c *fiber.Ctx) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	groupRefKey := c.Params("groupRefKey")
	var group models.Group
	defer cancel()

	objId, _ := primitive.ObjectIDFromHex(groupRefKey)

	err := groupCollection.FindOne(ctx, bson.M{"id": objId}).Decode(&group)
	if err != nil {
		return c.Status(http.StatusInternalServerError).JSON(responses.GroupResponse{Status: http.StatusInternalServerError, Message: "error", Data: &fiber.Map{"data": err.Error()}})
	}

	return c.Status(http.StatusOK).JSON(responses.GroupResponse{Status: http.StatusOK, Message: "success", Data: &fiber.Map{"data": group}})
}

func DeleteAGroup(c *fiber.Ctx) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	groupRefKey := c.Params("groupRefKey")
	defer cancel()

	objId, _ := primitive.ObjectIDFromHex(groupRefKey)

	result, err := groupCollection.DeleteOne(ctx, bson.M{"id": objId})
	if err != nil {
		return c.Status(http.StatusInternalServerError).JSON(responses.GroupResponse{Status: http.StatusInternalServerError, Message: "error", Data: &fiber.Map{"data": err.Error()}})
	}

	if result.DeletedCount < 1 {
		return c.Status(http.StatusNotFound).JSON(
			responses.GroupResponse{Status: http.StatusNotFound, Message: "error", Data: &fiber.Map{"data": "Group with specified ID not found!"}},
		)
	}

	return c.Status(http.StatusOK).JSON(
		responses.GroupResponse{Status: http.StatusOK, Message: "success", Data: &fiber.Map{"data": "Group successfully deleted!"}},
	)
}
