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
)

var groupCollection *mongo.Collection = configs.GetCollection(configs.DB, "groups")
var membershipCollection *mongo.Collection = configs.GetCollection(configs.DB, "memberships")
var groupValidate = validator.New()

// create group
func CreateGroup(c *fiber.Ctx) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var group models.Group
	if err := c.BodyParser(&group); err != nil {
		return c.Status(http.StatusBadRequest).JSON(responses.GroupResponse{
			Status:  http.StatusBadRequest,
			Message: "Failed to parse the request body",
			Data:    &fiber.Map{"error": err.Error()},
		})
	}

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
		Desc:      group.Desc,
		Status:    true,
	}

	result, err := groupCollection.InsertOne(ctx, newGroup)
	if err != nil {
		return c.Status(http.StatusInternalServerError).JSON(responses.GroupResponse{
			Status:  http.StatusInternalServerError,
			Message: "Failed to insert group",
			Data:    &fiber.Map{"error": err.Error()},
		})
	}

	// ambil local user
	user := c.Locals("user")
	userClaims, ok := user.(jwt.MapClaims)
	if !ok {
		return c.Status(http.StatusInternalServerError).JSON(responses.GroupResponse{
			Status:  http.StatusInternalServerError,
			Message: "Failed to get user claims from context",
			Data:    &fiber.Map{"error": "user claims not found or not a MapClaims"},
		})
	}

	userID, ok := userClaims["id"].(string)
	if !ok {
		return c.Status(http.StatusInternalServerError).JSON(responses.GroupResponse{
			Status:  http.StatusInternalServerError,
			Message: "Failed to get user ID from claims",
			Data:    &fiber.Map{"error": "user ID not found or not a string"},
		})
	}

	memberID, err := primitive.ObjectIDFromHex(userID)
	if err != nil {
		return c.Status(http.StatusInternalServerError).JSON(responses.GroupResponse{
			Status:  http.StatusInternalServerError,
			Message: "Failed to convert member ID",
			Data:    &fiber.Map{"error": err.Error()},
		})
	}

	membershipWithIsAdmin := models.Membership{
		ID:        primitive.NewObjectID(),
		ID_Member: memberID,
		ID_Group:  result.InsertedID.(primitive.ObjectID),
		IsAdmin:   true,
		IsAllowed: true,
	}

	_, err = membershipCollection.InsertOne(ctx, membershipWithIsAdmin)
	if err != nil {
		return c.Status(http.StatusInternalServerError).JSON(responses.GroupResponse{
			Status:  http.StatusInternalServerError,
			Message: "Failed to insert membership",
			Data:    &fiber.Map{"error": err.Error()},
		})
	}

	return c.Status(http.StatusCreated).JSON(responses.GroupResponse{
		Status:  http.StatusCreated,
		Message: "Group created successfully",
		Data:    &fiber.Map{"groupId": result.InsertedID},
	})
}

// fungsi untuk mendapatkan group dari groupRefKey
func GetAGroup(c *fiber.Ctx) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	groupRefKey := c.Params("groupRefKey")
	var group models.Group
	defer cancel()

	err := groupCollection.FindOne(ctx, bson.M{"refkey": groupRefKey}).Decode(&group)
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

	return c.Status(http.StatusOK).JSON(responses.GroupResponse{Status: http.StatusOK, Message: "success", Data: &fiber.Map{"data": group}})
}

// fungsi untuk deaktivasi sebuah group
func DeactivateAGroup(c *fiber.Ctx) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	groupRefKey := c.Params("groupRefkey")
	var group models.Group
	defer cancel()

	err := groupCollection.FindOne(ctx, bson.M{"refkey": groupRefKey}).Decode(&group)
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

	// jika current loggedin user adalah admin di group tersebut maka akan user dapat melakukan deaktivasi group
	if isAdmin {
		update := bson.M{"status": false}
		result, err := groupCollection.UpdateOne(ctx, bson.M{"_id": group.ID}, bson.M{"$set": update})
		if err != nil {
			return c.Status(http.StatusInternalServerError).JSON(responses.GroupResponse{Status: http.StatusInternalServerError, Message: "error", Data: &fiber.Map{"data": err.Error()}})
		}

		if result.MatchedCount != 1 {
			return c.Status(http.StatusNotFound).JSON(responses.GroupResponse{
				Status:  http.StatusNotFound,
				Message: "Group not found",
				Data:    nil,
			})
		}
	} else {
		return c.Status(http.StatusUnauthorized).JSON(
			responses.GroupResponse{Status: http.StatusUnauthorized, Message: "failed", Data: &fiber.Map{"data": "Unauthorized"}},
		)
	}

	return c.Status(http.StatusOK).JSON(
		responses.GroupResponse{Status: http.StatusOK, Message: "success", Data: &fiber.Map{"data": "Group successfully deactivated!"}},
	)
}

// fungsi untuk aktivasi sebuah group
func ActivateAGroup(c *fiber.Ctx) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	groupRefKey := c.Params("groupRefkey")
	var group models.Group
	defer cancel()

	err := groupCollection.FindOne(ctx, bson.M{"refkey": groupRefKey}).Decode(&group)
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

	// jika current loggedin user adalah admin di group tersebut maka akan user dapat melakukan aktivasi group
	if isAdmin {
		update := bson.M{"status": true}
		result, err := groupCollection.UpdateOne(ctx, bson.M{"_id": group.ID}, bson.M{"$set": update})
		if err != nil {
			return c.Status(http.StatusInternalServerError).JSON(responses.GroupResponse{Status: http.StatusInternalServerError, Message: "error", Data: &fiber.Map{"data": err.Error()}})
		}

		if result.MatchedCount != 1 {
			return c.Status(http.StatusNotFound).JSON(responses.GroupResponse{
				Status:  http.StatusNotFound,
				Message: "Group not found",
				Data:    nil,
			})
		}
	} else {
		return c.Status(http.StatusUnauthorized).JSON(
			responses.GroupResponse{Status: http.StatusUnauthorized, Message: "failed", Data: &fiber.Map{"data": "Unauthorized"}},
		)
	}

	return c.Status(http.StatusOK).JSON(
		responses.GroupResponse{Status: http.StatusOK, Message: "success", Data: &fiber.Map{"data": "Group successfully activated!"}},
	)
}

// fungsi untuk join group
func JoinGroup(c *fiber.Ctx) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	groupRefKey := c.Params("groupRefKey")

	var group models.Group

	err := groupCollection.FindOne(ctx, bson.M{"refkey": groupRefKey}).Decode(&group)
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

	// mengecek apakah user telah loggedin atau tidak
	user := c.Locals("user")
	userClaims, ok := user.(jwt.MapClaims)
	if !ok {
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{
			"error":   "Failed to get user claims from context",
			"message": "Internal Server Error",
		})
	}

	memberIDHex, ok := userClaims["id"].(string)
	if !ok {
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{
			"error":   "Failed to get user ID from claims",
			"message": "Internal Server Error",
		})
	}

	memberID, err := primitive.ObjectIDFromHex(memberIDHex)
	if err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{
			"error":   err.Error(),
			"message": "Bad Request",
		})
	}

	// mengecek apakah user telah masuk ke group atau tidak sehinggga tidak ada double entry
	var existingMembership models.Membership
	err = membershipCollection.FindOne(
		ctx,
		bson.M{"id_member": memberID, "id_group": group.ID},
	).Decode(&existingMembership)

	if err == nil {
		return c.Status(fiber.StatusConflict).JSON(fiber.Map{
			"message": "User is already requested to join the group",
		})
	} else if err != mongo.ErrNoDocuments {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error":   "Error checking membership",
			"message": "Internal Server Error",
		})
	}

	newMembership := models.Membership{
		ID:        primitive.NewObjectID(),
		ID_Member: memberID,
		ID_Group:  group.ID,
		IsAdmin:   false,
		IsAllowed: false,
	}

	// masukkan ke membership
	_, err = membershipCollection.InsertOne(ctx, newMembership)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error":   "Failed to create membership",
			"message": "Internal Server Error",
		})
	}

	return c.Status(fiber.StatusCreated).JSON(fiber.Map{
		"message": "User successfully requested to join the group",
	})
}

func GetMemberGroups(memberID primitive.ObjectID) ([]models.Group, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// mirip syarat join pada SQL dengan menggunakan $match
	matchStage := bson.D{primitive.E{Key: "$match",
		Value: bson.D{
			{Key: "id_member", Value: memberID},
			{Key: "is_allowed", Value: true},
		}}}

	// lookup mirip join dari SQL, menggabungkan data dari collection groups berdasarkan id_group
	// {Key: "from", Value: "groups"}: kita akan melakukan lookup pada collection groups.
	// {Key: "localField", Value: "id_group"}: atribut id_group pada collection membershipCollection akan digunakan untuk pencocokan.
	// {Key: "foreignField", Value: "_id"}: id_group dari membershipCollection akan dicocokkan dengan atribut _id pada collection groups.
	// {Key: "as", Value: "group"}: hasil dalam bentuk array akan diberi namanya group

	lookupStage := bson.D{
		{Key: "$lookup", Value: bson.D{
			{Key: "from", Value: "groups"},
			{Key: "localField", Value: "id_group"},
			{Key: "foreignField", Value: "_id"},
			{Key: "as", Value: "group"},
		}},
	}

	// berfungsi untuk merapikan hasil lookup sehingga setiap elemen array jadi document terpisah
	unwindStage := bson.D{primitive.E{Key: "$unwind", Value: "$group"}}

	// berfungsi untuk menentukan output atau hasil dari lookup
	projectStage := bson.D{primitive.E{
		Key: "$project",
		Value: bson.D{
			{Key: "_id", Value: "$group._id"},
			{Key: "NamaGroup", Value: "$group.namagroup"},
			{Key: "Desc", Value: "$group.desc"},
			{Key: "RefKey", Value: "$group.refkey"},
			{Key: "Status", Value: "$group.status"},
		},
	}}

	// proses aggregasi
	cursor, err := membershipCollection.Aggregate(ctx, mongo.Pipeline{matchStage, lookupStage, unwindStage, projectStage})
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var groups []models.Group
	// setiap elemen dari hasil aggregasi dimasukkan ke array groups
	for cursor.Next(ctx) {
		var group models.Group
		if err := cursor.Decode(&group); err != nil {
			return nil, err
		}
		groups = append(groups, group)
	}

	return groups, nil
}

// fungsi yang mengambil semua group yang user join
func GetAllJoinedGroup(c *fiber.Ctx) error {
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

	memberID, err := primitive.ObjectIDFromHex(memberIDHex)

	if err != nil {
		return c.Status(http.StatusBadRequest).JSON(responses.DendaResponse{
			Status:  http.StatusBadRequest,
			Message: "Invalid member ID",
		})
	}

	memberGroups, err := GetMemberGroups(memberID)
	if err != nil {
		// Handle the error
		return c.Status(http.StatusBadRequest).JSON(responses.DendaResponse{
			Status:  http.StatusBadRequest,
			Message: "Invalid member group",
		})
	}

	return c.Status(http.StatusOK).JSON(responses.DendaResponse{
		Status:  http.StatusOK,
		Message: "Success",
		Data:    &fiber.Map{"groups": memberGroups},
	})

}
