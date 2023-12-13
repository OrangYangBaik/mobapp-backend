package controllers

import (
	"context"
	"fiber-mongo-api/configs"
	"fiber-mongo-api/models"
	"fiber-mongo-api/responses"
	"fmt"
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
var Validate = validator.New()

func SemuaMember(c *fiber.Ctx) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var members []models.Member
	cursor, err := memberCollection.Find(ctx, bson.M{})
	if err != nil {
		return c.Status(http.StatusInternalServerError).JSON(responses.MemberResponse{
			Status:  http.StatusInternalServerError,
			Message: "Error retrieving members",
			Data:    &fiber.Map{"data": err.Error()},
		})
	}
	defer cursor.Close(ctx)

	if err := cursor.All(ctx, &members); err != nil {
		return c.Status(http.StatusInternalServerError).JSON(responses.MemberResponse{
			Status:  http.StatusInternalServerError,
			Message: "Error decoding members",
			Data:    &fiber.Map{"data": err.Error()},
		})
	}

	return c.Status(http.StatusOK).JSON(responses.MemberResponse{
		Status:  http.StatusOK,
		Message: "success",
		Data:    &fiber.Map{"data": members},
	})
}

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

func GetProfile(c *fiber.Ctx) error {
	user := c.Locals("user")
	// userClaims, ok := user.(jwt.MapClaims)
	// if !ok {
	// 	return c.Status(http.StatusInternalServerError).JSON(responses.GroupResponse{
	// 		Status:  http.StatusInternalServerError,
	// 		Message: "Failed to get user claims from context",
	// 		Data:    &fiber.Map{"error": "user claims not found or not a MapClaims"},
	// 	})
	// }

	return c.Status(http.StatusCreated).JSON(responses.GroupResponse{
		Status:  http.StatusCreated,
		Message: "Here is your profile",
		Data:    &fiber.Map{"profile": user},
	})
}

func GetAMember(c *fiber.Ctx) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	memberId := c.Params("MemberId")
	groupRefKey := c.Params("groupRefKey")
	var member models.Member
	defer cancel()

	user := c.Locals("user")
	userClaims, ok := user.(jwt.MapClaims)
	if !ok {
		return c.Status(http.StatusInternalServerError).JSON(responses.GroupResponse{
			Status:  http.StatusInternalServerError,
			Message: "Failed to get user claims from context",
			Data:    &fiber.Map{"error": "user claims not found or not a MapClaims"},
		})
	}

	memberIDHex, ok := userClaims["id"].(string)
	if !ok {
		return c.Status(http.StatusInternalServerError).JSON(responses.GroupResponse{
			Status:  http.StatusInternalServerError,
			Message: "Failed to get user ID from claims",
			Data:    &fiber.Map{"error": "user ID not found or not a string"},
		})
	}

	isAdmin, err := checkAdmin(ctx, memberIDHex, groupRefKey)
	if err != nil {
		return c.Status(http.StatusInternalServerError).JSON(responses.GroupResponse{
			Status:  http.StatusInternalServerError,
			Message: "Error checking admin status",
			Data:    &fiber.Map{"error": err.Error()},
		})
	}

	if !isAdmin {
		return c.Status(http.StatusUnauthorized).JSON(responses.GroupResponse{
			Status:  http.StatusUnauthorized,
			Message: "Unauthorized, only group admin can retrieve all members",
			Data:    nil,
		})
	}

	objId, _ := primitive.ObjectIDFromHex(memberId)

	err = memberCollection.FindOne(ctx, bson.M{"_id": objId}).Decode(&member)
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

	result, err := memberCollection.UpdateOne(ctx, bson.M{"_id": objId}, bson.M{"$set": update})

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

func checkAdmin(ctx context.Context, memberIDHex, groupRefKey string) (bool, error) {
	var group models.Group
	err := groupCollection.FindOne(ctx, bson.M{"refkey": groupRefKey}).Decode(&group)
	if err != nil {
		return false, err
	}

	memberID, err := primitive.ObjectIDFromHex(memberIDHex)

	var membership models.Membership
	err = membershipCollection.FindOne(ctx, bson.M{"id_member": memberID, "id_group": group.ID}).Decode(&membership)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return false, nil
		}
		return false, err
	}

	return membership.IsAdmin, nil
}

func GetAllMember(c *fiber.Ctx) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	groupRefKey := c.Params("groupRefKey")
	var members []models.Member
	var memberships []models.Membership
	var group models.Group
	defer cancel()

	user := c.Locals("user")
	userClaims, ok := user.(jwt.MapClaims)
	if !ok {
		return c.Status(http.StatusInternalServerError).JSON(responses.GroupResponse{
			Status:  http.StatusInternalServerError,
			Message: "Failed to get user claims from context",
			Data:    &fiber.Map{"error": "user claims not found or not a MapClaims"},
		})
	}

	memberIDHex, ok := userClaims["id"].(string)
	if !ok {
		return c.Status(http.StatusInternalServerError).JSON(responses.GroupResponse{
			Status:  http.StatusInternalServerError,
			Message: "Failed to get user ID from claims",
			Data:    &fiber.Map{"error": "user ID not found or not a string"},
		})
	}

	isAdmin, err := checkAdmin(ctx, memberIDHex, groupRefKey)
	if err != nil {
		return c.Status(http.StatusInternalServerError).JSON(responses.GroupResponse{
			Status:  http.StatusInternalServerError,
			Message: "Error checking admin status",
			Data:    &fiber.Map{"error": err.Error()},
		})
	}

	if !isAdmin {
		return c.Status(http.StatusUnauthorized).JSON(responses.GroupResponse{
			Status:  http.StatusUnauthorized,
			Message: "Unauthorized, only group admin can retrieve all members",
			Data:    nil,
		})
	}

	err = groupCollection.FindOne(ctx, bson.M{"refkey": groupRefKey}).Decode(&group)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return c.Status(http.StatusNotFound).JSON(responses.GroupResponse{
				Status:  http.StatusNotFound,
				Message: "Group not found",
				Data:    nil,
			})
		}

		return c.Status(http.StatusInternalServerError).JSON(responses.GroupResponse{
			Status:  http.StatusInternalServerError,
			Message: "Error retrieving group",
			Data:    &fiber.Map{"data": err.Error()},
		})
	}

	cursor, err := membershipCollection.Find(ctx, bson.M{"id_group": group.ID})
	if err != nil {
		return c.Status(http.StatusInternalServerError).JSON(responses.GroupResponse{
			Status:  http.StatusInternalServerError,
			Message: "Error retrieving memberships",
			Data:    &fiber.Map{"data": err.Error()},
		})
	}
	defer cursor.Close(ctx)

	if err := cursor.All(ctx, &memberships); err != nil {
		return c.Status(http.StatusInternalServerError).JSON(responses.GroupResponse{
			Status:  http.StatusInternalServerError,
			Message: "Error decoding memberships",
			Data:    &fiber.Map{"data": err.Error()},
		})
	}

	for _, membership := range memberships {
		var member models.Member
		err := memberCollection.FindOne(ctx, bson.M{"_id": membership.ID_Member}).Decode(&member)
		if err != nil {
			return c.Status(http.StatusInternalServerError).JSON(responses.GroupResponse{
				Status:  http.StatusInternalServerError,
				Message: "Error retrieving member",
				Data:    &fiber.Map{"data": err.Error()},
			})
		}
		members = append(members, member)
	}

	return c.Status(http.StatusOK).JSON(
		responses.MemberResponse{Status: http.StatusOK, Message: "success", Data: &fiber.Map{"data": members}},
	)
}

func KickAMember(c *fiber.Ctx) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	type KickRequest struct {
		GroupRefKey      string `json:"groupRefKey" form:"string" validate:"required"`
		MemberToBeKicked string `json:"memberID" form:"string" validate:"required"`
	}

	user := c.Locals("user")
	fmt.Println(user)
	userClaims, ok := user.(jwt.MapClaims)
	if !ok {
		return c.Status(http.StatusInternalServerError).JSON(responses.GroupResponse{
			Status:  http.StatusInternalServerError,
			Message: "Failed to get user claims from context",
			Data:    &fiber.Map{"error": "user claims not found or not a MapClaims"},
		})
	}

	memberIDHex, ok := userClaims["id"].(string)
	if !ok {
		return c.Status(http.StatusInternalServerError).JSON(responses.GroupResponse{
			Status:  http.StatusInternalServerError,
			Message: "Failed to get user ID from claims",
			Data:    &fiber.Map{"error": "user ID not found or not a string"},
		})
	}

	var kickReq KickRequest
	if err := c.BodyParser(&kickReq); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"message": "Failed to parse the request body"})
	}

	if err := Validate.Struct(kickReq); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"message": err.Error()})
	}

	isAdmin, err := checkAdmin(ctx, memberIDHex, kickReq.GroupRefKey)
	if err != nil {
		return c.Status(http.StatusInternalServerError).JSON(responses.GroupResponse{
			Status:  http.StatusInternalServerError,
			Message: "Error checking admin status",
			Data:    &fiber.Map{"error": err.Error()},
		})
	}

	if !isAdmin {
		return c.Status(http.StatusUnauthorized).JSON(responses.GroupResponse{
			Status:  http.StatusUnauthorized,
			Message: "Unauthorized, only group admin can retrieve all members",
			Data:    nil,
		})
	}

	var group models.Group
	err = groupCollection.FindOne(ctx, bson.M{"refkey": kickReq.GroupRefKey}).Decode(&group)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return c.Status(http.StatusNotFound).JSON(responses.GroupResponse{
				Status:  http.StatusNotFound,
				Message: "Group not found",
				Data:    nil,
			})
		}

		return c.Status(http.StatusInternalServerError).JSON(responses.GroupResponse{
			Status:  http.StatusInternalServerError,
			Message: "Error retrieving group",
			Data:    &fiber.Map{"data": err.Error()},
		})
	}

	memberToBeKickedID, err := primitive.ObjectIDFromHex(kickReq.MemberToBeKicked)

	isMemberAdmin, err := checkAdmin(ctx, kickReq.MemberToBeKicked, kickReq.GroupRefKey)
	if err != nil {
		return c.Status(http.StatusInternalServerError).JSON(responses.GroupResponse{
			Status:  http.StatusInternalServerError,
			Message: "Error checking admin status",
			Data:    &fiber.Map{"error": err.Error()},
		})
	}

	if isMemberAdmin {
		return c.Status(http.StatusUnauthorized).JSON(responses.GroupResponse{
			Status:  http.StatusUnauthorized,
			Message: "Unauthorized, the member is admin",
		})
	}

	result, err := membershipCollection.DeleteOne(ctx, bson.M{"id_group": group.ID, "id_member": memberToBeKickedID})
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return c.Status(http.StatusNotFound).JSON(responses.GroupResponse{
				Status:  http.StatusNotFound,
				Message: "Membership not found",
			})
		}
	}

	if result.DeletedCount < 1 {
		return c.Status(http.StatusNotFound).JSON(
			responses.GroupResponse{Status: http.StatusNotFound, Message: "error", Data: &fiber.Map{"data": "Membership with specified ID not found!"}},
		)
	}

	return c.Status(http.StatusOK).JSON(
		responses.GroupResponse{Status: http.StatusOK, Message: "success", Data: &fiber.Map{"data": "Member successfully kicked!"}},
	)
}

func GiveAdmin(c *fiber.Ctx) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	type GiveAdminRequest struct {
		GroupRefKey     string `json:"groupRefKey" form:"string" validate:"required"`
		MemberToBeAdmin string `json:"memberID" form:"string" validate:"required"`
	}

	user := c.Locals("user")
	//fmt.Println(user)
	userClaims, ok := user.(jwt.MapClaims)
	if !ok {
		return c.Status(http.StatusInternalServerError).JSON(responses.GroupResponse{
			Status:  http.StatusInternalServerError,
			Message: "Failed to get user claims from context",
			Data:    &fiber.Map{"error": "user claims not found or not a MapClaims"},
		})
	}

	memberIDHex, ok := userClaims["id"].(string)
	if !ok {
		return c.Status(http.StatusInternalServerError).JSON(responses.GroupResponse{
			Status:  http.StatusInternalServerError,
			Message: "Failed to get user ID from claims",
			Data:    &fiber.Map{"error": "user ID not found or not a string"},
		})
	}

	var adminReq GiveAdminRequest
	if err := c.BodyParser(&adminReq); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"message": "Failed to parse the request body"})
	}

	if err := Validate.Struct(adminReq); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"message": err.Error()})
	}

	isAdmin, err := checkAdmin(ctx, memberIDHex, adminReq.GroupRefKey)
	if err != nil {
		return c.Status(http.StatusInternalServerError).JSON(responses.GroupResponse{
			Status:  http.StatusInternalServerError,
			Message: "Error checking admin status",
			Data:    &fiber.Map{"error": err.Error()},
		})
	}

	if !isAdmin {
		return c.Status(http.StatusUnauthorized).JSON(responses.GroupResponse{
			Status:  http.StatusUnauthorized,
			Message: "Unauthorized, only group admin can retrieve all members",
			Data:    nil,
		})
	}

	var group models.Group
	err = groupCollection.FindOne(ctx, bson.M{"refkey": adminReq.GroupRefKey}).Decode(&group)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return c.Status(http.StatusNotFound).JSON(responses.GroupResponse{
				Status:  http.StatusNotFound,
				Message: "Group not found",
				Data:    nil,
			})
		}

		return c.Status(http.StatusInternalServerError).JSON(responses.GroupResponse{
			Status:  http.StatusInternalServerError,
			Message: "Error retrieving group",
			Data:    &fiber.Map{"data": err.Error()},
		})
	}

	update := bson.M{"isadmin": true}
	memberToBeAdminID, err := primitive.ObjectIDFromHex(adminReq.MemberToBeAdmin)
	result, err := membershipCollection.UpdateOne(
		ctx,
		bson.M{"id_member": memberToBeAdminID, "id_group": group.ID},
		bson.M{"$set": update})

	if err != nil {
		return c.Status(http.StatusInternalServerError).JSON(responses.GroupResponse{
			Status:  http.StatusInternalServerError,
			Message: "Error updating membership",
			Data:    &fiber.Map{"error": err.Error()},
		})
	}

	if result.MatchedCount != 1 {
		return c.Status(http.StatusNotFound).JSON(responses.GroupResponse{
			Status:  http.StatusNotFound,
			Message: "Membership not found",
			Data:    nil,
		})
	}

	return c.Status(http.StatusOK).JSON(responses.GroupResponse{
		Status:  http.StatusOK,
		Message: "success",
		Data:    &fiber.Map{"message": "Membership updated successfully"},
	})

}

func RevokeAdmin(c *fiber.Ctx) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	type RevokeAdminRequest struct {
		GroupRefKey       string `json:"groupRefKey" form:"string" validate:"required"`
		MemberToBeRevoked string `json:"memberID" form:"string" validate:"required"`
	}

	user := c.Locals("user")
	//fmt.Println(user)
	userClaims, ok := user.(jwt.MapClaims)
	if !ok {
		return c.Status(http.StatusInternalServerError).JSON(responses.GroupResponse{
			Status:  http.StatusInternalServerError,
			Message: "Failed to get user claims from context",
			Data:    &fiber.Map{"error": "user claims not found or not a MapClaims"},
		})
	}

	memberIDHex, ok := userClaims["id"].(string)
	if !ok {
		return c.Status(http.StatusInternalServerError).JSON(responses.GroupResponse{
			Status:  http.StatusInternalServerError,
			Message: "Failed to get user ID from claims",
			Data:    &fiber.Map{"error": "user ID not found or not a string"},
		})
	}

	var revokeAdminReq RevokeAdminRequest
	if err := c.BodyParser(&revokeAdminReq); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"message": "Failed to parse the request body"})
	}

	if err := Validate.Struct(revokeAdminReq); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"message": err.Error()})
	}

	//cek user admin ga
	isAdmin, err := checkAdmin(ctx, memberIDHex, revokeAdminReq.GroupRefKey)
	if err != nil {
		return c.Status(http.StatusInternalServerError).JSON(responses.GroupResponse{
			Status:  http.StatusInternalServerError,
			Message: "Error checking admin status",
			Data:    &fiber.Map{"error": err.Error()},
		})
	}

	if !isAdmin {
		return c.Status(http.StatusUnauthorized).JSON(responses.GroupResponse{
			Status:  http.StatusUnauthorized,
			Message: "Unauthorized, only group admin can retrieve all members",
			Data:    nil,
		})
	}

	var group models.Group
	err = groupCollection.FindOne(ctx, bson.M{"refkey": revokeAdminReq.GroupRefKey}).Decode(&group)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return c.Status(http.StatusNotFound).JSON(responses.GroupResponse{
				Status:  http.StatusNotFound,
				Message: "Group not found",
				Data:    nil,
			})
		}

		return c.Status(http.StatusInternalServerError).JSON(responses.GroupResponse{
			Status:  http.StatusInternalServerError,
			Message: "Error retrieving group",
			Data:    &fiber.Map{"data": err.Error()},
		})
	}

	update := bson.M{"isadmin": false}
	memberToBeRevokedID, err := primitive.ObjectIDFromHex(revokeAdminReq.MemberToBeRevoked)
	result, err := membershipCollection.UpdateOne(
		ctx,
		bson.M{"id_member": memberToBeRevokedID, "id_group": group.ID},
		bson.M{"$set": update})

	if err != nil {
		return c.Status(http.StatusInternalServerError).JSON(responses.GroupResponse{
			Status:  http.StatusInternalServerError,
			Message: "Error updating membership",
			Data:    &fiber.Map{"error": err.Error()},
		})
	}

	if result.MatchedCount != 1 {
		return c.Status(http.StatusNotFound).JSON(responses.GroupResponse{
			Status:  http.StatusNotFound,
			Message: "Membership not found",
			Data:    nil,
		})
	}

	return c.Status(http.StatusOK).JSON(responses.GroupResponse{
		Status:  http.StatusOK,
		Message: "success",
		Data:    &fiber.Map{"message": "Membership updated successfully"},
	})

}
