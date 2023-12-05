package controllers

import (
	"context"
	"fiber-mongo-api/configs"
	"fiber-mongo-api/models"
	"fiber-mongo-api/responses"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
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

	if err := c.BodyParser(&member); err != nil {
		return c.Status(http.StatusBadRequest).JSON(responses.MemberResponse{
			Status:  http.StatusBadRequest,
			Message: "Failed to parse the request body",
			Data:    &fiber.Map{"error": err.Error()},
		})
	}

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

func LoginMember(c *fiber.Ctx) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	type LoginRequest struct {
		Email    string `json:"email" form:"email" validate:"required,email"`
		Password string `json:"password" form:"password" validate:"required"`
	}

	var loginRequest LoginRequest

	if err := c.BodyParser(&loginRequest); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"message": "Failed to parse the request body"})
	}

	if err := memberValidate.Struct(loginRequest); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"message": err.Error()})
	}

	//ctx := context.Background()
	//db := configs.DB
	//memberCollection := configs.GetCollection(db, "members")

	//cek di datbes
	var member models.Member
	err := memberCollection.FindOne(ctx, bson.M{"email": loginRequest.Email}).Decode(&member)
	if err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"message": "Invalid email or password 1"})
	}

	//cek sama ga
	if err := configs.ComparePasswords(member.Password, loginRequest.Password); err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"message": "Invalid email or password 2"})
	}

	token := jwt.New(jwt.SigningMethodHS256)
	claims := token.Claims.(jwt.MapClaims)

	claims["id"] = member.ID.Hex()
	claims["nama"] = member.Nama
	claims["nim"] = member.NIM
	claims["email"] = member.Email
	claims["prodi"] = member.Prodi
	claims["angkatan"] = member.Angkatan
	claims["exp"] = time.Now().Add(time.Hour * 24).Unix() // Token expires in 24 hours

	tokenString, err := token.SignedString([]byte(configs.JWTSecretKey))
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"message": "Failed to generate JWT token"})
	}

	return c.JSON(fiber.Map{"message": "Login successful", "token": tokenString})
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

	if err := c.BodyParser(&member); err != nil {
		return c.Status(http.StatusBadRequest).JSON(responses.MemberResponse{Status: http.StatusBadRequest, Message: "error", Data: &fiber.Map{"data": err.Error()}})
	}

	if validationErr := memberValidate.Struct(&member); validationErr != nil {
		return c.Status(http.StatusBadRequest).JSON(responses.MemberResponse{Status: http.StatusBadRequest, Message: "error", Data: &fiber.Map{"data": validationErr.Error()}})
	}

	hashedPassword, err := hashPassword(member.Password)
	update := bson.M{"nama": member.Nama, "nim": member.NIM, "password": hashedPassword, "email": member.Email, "prodi": member.Prodi, "angkatan": member.Angkatan}

	result, err := memberCollection.UpdateOne(ctx, bson.M{"id": objId}, bson.M{"$set": update})

	if err != nil {
		return c.Status(http.StatusInternalServerError).JSON(responses.MemberResponse{Status: http.StatusInternalServerError, Message: "error", Data: &fiber.Map{"data": err.Error()}})
	}

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
