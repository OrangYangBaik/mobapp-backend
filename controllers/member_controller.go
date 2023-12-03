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
	"golang.org/x/crypto/bcrypt"
)

var memberCollection *mongo.Collection = configs.GetCollection(configs.DB, "members")
var memberValidate = validator.New()

func hashPassword(password string) (string, error) {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hashedPassword), nil
}

func CreateMember(c *fiber.Ctx) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var member models.Member

	// Validate the request body
	if err := c.BodyParser(&member); err != nil {
		return c.Status(http.StatusBadRequest).JSON(responses.MemberResponse{
			Status:  http.StatusBadRequest,
			Message: "Failed to parse the request body",
			Data:    &fiber.Map{"error": err.Error()},
		})
	}

	// Use the validator library to validate required fields
	if validationErr := memberValidate.Struct(&member); validationErr != nil {
		return c.Status(http.StatusBadRequest).JSON(responses.MemberResponse{
			Status:  http.StatusBadRequest,
			Message: "Validation failed",
			Data:    &fiber.Map{"error": validationErr.Error()},
		})
	}

	password := member.Password
	hashedPassword, err := hashPassword(password)

	if err != nil {
		// Handle the error more gracefully, perhaps log and return a user-friendly message
		return c.Status(http.StatusInternalServerError).JSON(responses.MemberResponse{
			Status:  http.StatusInternalServerError,
			Message: "Failed to hash the password",
			Data:    &fiber.Map{"error": err.Error()},
		})
	}

	newMember := models.Member{
		ID:       primitive.NewObjectID(),
		Nama:     member.Nama,
		NIM:      member.NIM,
		Password: hashedPassword,
		Email:    member.Email,
		Prodi:    member.Prodi,
		Angkatan: member.Angkatan,
	}

	result, err := memberCollection.InsertOne(ctx, newMember)
	if err != nil {
		// Handle the error more gracefully, perhaps log and return a user-friendly message
		return c.Status(http.StatusInternalServerError).JSON(responses.MemberResponse{
			Status:  http.StatusInternalServerError,
			Message: "Failed to insert member",
			Data:    &fiber.Map{"error": err.Error()},
		})
	}

	return c.Status(http.StatusCreated).JSON(responses.MemberResponse{
		Status:  http.StatusCreated,
		Message: "Member created successfully",
		Data:    &fiber.Map{"memberId": result.InsertedID},
	})
}

func GetAMember(c *fiber.Ctx) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	memberId := c.Params("MemberId")
	var member models.Member
	defer cancel()

	objId, _ := primitive.ObjectIDFromHex(memberId)

	err := memberCollection.FindOne(ctx, bson.M{"id": objId}).Decode(&member)
	if err != nil {
		return c.Status(http.StatusInternalServerError).JSON(responses.MemberResponse{Status: http.StatusInternalServerError, Message: "error", Data: &fiber.Map{"data": err.Error()}})
	}

	return c.Status(http.StatusOK).JSON(responses.MemberResponse{Status: http.StatusOK, Message: "success", Data: &fiber.Map{"data": member}})
}

func EditAMember(c *fiber.Ctx) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	memberId := c.Params("memberId")
	var member models.Member
	defer cancel()

	objId, _ := primitive.ObjectIDFromHex(memberId)

	//validate the request body
	if err := c.BodyParser(&member); err != nil {
		return c.Status(http.StatusBadRequest).JSON(responses.MemberResponse{Status: http.StatusBadRequest, Message: "error", Data: &fiber.Map{"data": err.Error()}})
	}

	//use the validator library to validate required fields
	if validationErr := memberValidate.Struct(&member); validationErr != nil {
		return c.Status(http.StatusBadRequest).JSON(responses.MemberResponse{Status: http.StatusBadRequest, Message: "error", Data: &fiber.Map{"data": validationErr.Error()}})
	}

	update := bson.M{"nama": member.Nama, "nim": member.NIM, "password": member.Password, "email": member.Email, "prodi": member.Prodi, "angkatan": member.Angkatan}

	result, err := memberCollection.UpdateOne(ctx, bson.M{"id": objId}, bson.M{"$set": update})

	if err != nil {
		return c.Status(http.StatusInternalServerError).JSON(responses.MemberResponse{Status: http.StatusInternalServerError, Message: "error", Data: &fiber.Map{"data": err.Error()}})
	}
	//get updated user details
	var updatedMember models.Member
	if result.MatchedCount == 1 {
		err := memberCollection.FindOne(ctx, bson.M{"id": objId}).Decode(&updatedMember)

		if err != nil {
			return c.Status(http.StatusInternalServerError).JSON(responses.MemberResponse{Status: http.StatusInternalServerError, Message: "error", Data: &fiber.Map{"data": err.Error()}})
		}
	}

	return c.Status(http.StatusOK).JSON(responses.MemberResponse{Status: http.StatusOK, Message: "success", Data: &fiber.Map{"data": updatedMember}})
}

func DeleteAMember(c *fiber.Ctx) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	memberId := c.Params("memberId")
	defer cancel()

	objId, _ := primitive.ObjectIDFromHex(memberId)

	result, err := memberCollection.DeleteOne(ctx, bson.M{"id": objId})
	if err != nil {
		return c.Status(http.StatusInternalServerError).JSON(responses.MemberResponse{Status: http.StatusInternalServerError, Message: "error", Data: &fiber.Map{"data": err.Error()}})
	}

	if result.DeletedCount < 1 {
		return c.Status(http.StatusNotFound).JSON(
			responses.MemberResponse{Status: http.StatusNotFound, Message: "error", Data: &fiber.Map{"data": "Member with specified ID not found!"}},
		)
	}

	return c.Status(http.StatusOK).JSON(
		responses.MemberResponse{Status: http.StatusOK, Message: "success", Data: &fiber.Map{"data": "Member successfully deleted!"}},
	)
}

func GetAllMember(c *fiber.Ctx) error {
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
