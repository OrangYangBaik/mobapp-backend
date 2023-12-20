package controllers

import (
	"context"
	"fiber-mongo-api/configs"
	"fiber-mongo-api/models"
	"fiber-mongo-api/responses"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/go-playground/validator/v10"
	"github.com/gofiber/fiber/v2"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

var dendaCollection *mongo.Collection = configs.GetCollection(configs.DB, "dendas")
var dendaValidate = validator.New()

// mengecek apakah file berekstensi jpg jpeg atau png
func isJPGPNGFile(filename string) bool {
	ext := filepath.Ext(filename)
	return strings.EqualFold(ext, ".jpg") || strings.EqualFold(ext, ".jpeg") || strings.EqualFold(ext, ".png")
}

// fungsi create denda
func CreateDenda(c *fiber.Ctx) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	type DendaJSON struct {
		ID_Group  primitive.ObjectID `json:"id_group" validate:"required"`
		ID_Member primitive.ObjectID `json:"id_member" validate:"required"`
		Title     string             `json:"title" validate:"required"`
		Hari      string             `json:"hari" validate:"required"`
		Nominal   int                `json:"nominal" validate:"required"`
		Desc      string             `json:"desc" validate:"required"`
		IsPaid    bool               `json:"is_paid"`
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

	var dendaJSON DendaJSON
	if err := c.BodyParser(&dendaJSON); err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"message": "Failed to parse the JSON data"})
	}

	if err := Validate.Struct(dendaJSON); err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"message": err.Error()})
	}

	var group models.Group
	err := groupCollection.FindOne(ctx, bson.M{"_id": dendaJSON.ID_Group}).Decode(&group)
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

	isAdmin, err := checkAdmin(ctx, memberIDHex, group.RefKey)
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

	newDenda := models.Denda{
		ID:        primitive.NewObjectID(),
		ID_Member: dendaJSON.ID_Member,
		ID_Group:  dendaJSON.ID_Group,
		Title:     dendaJSON.Title,
		Hari:      dendaJSON.Hari,
		Nominal:   dendaJSON.Nominal,
		Desc:      dendaJSON.Desc,
		IsPaid:    dendaJSON.IsPaid,
	}

	result, err := dendaCollection.InsertOne(ctx, newDenda)
	if err != nil {
		return c.Status(http.StatusInternalServerError).JSON(responses.DendaResponse{
			Status:  http.StatusInternalServerError,
			Message: "Failed to insert denda",
			Data:    &fiber.Map{"error": err.Error()},
		})
	}

	return c.Status(http.StatusCreated).JSON(responses.DendaResponse{
		Status:  http.StatusCreated,
		Message: "Denda created successfully",
		Data:    &fiber.Map{"dendaId": result.InsertedID},
	})
}

// fungsi untuk delete denda
func DeleteADenda(c *fiber.Ctx) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	type DendaDeleteRequest struct {
		ID     primitive.ObjectID `json:"id_denda"`
		RefKey string             `json:"grouprefKey"`
	}

	var deleteReq DendaDeleteRequest

	if err := c.BodyParser(&deleteReq); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"message": "Failed to parse the request body"})
	}

	if err := memberValidate.Struct(deleteReq); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"message": err.Error()})
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

	isAdmin, err := checkAdmin(ctx, memberIDHex, deleteReq.RefKey)
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

	dendaID := primitive.ObjectID(deleteReq.ID)
	result, err := memberCollection.DeleteOne(ctx, bson.M{"_id": dendaID})
	if err != nil {
		return c.Status(http.StatusInternalServerError).JSON(responses.MemberResponse{Status: http.StatusInternalServerError, Message: "error", Data: &fiber.Map{"data": err.Error()}})
	}

	if result.DeletedCount < 1 {
		return c.Status(http.StatusNotFound).JSON(
			responses.MemberResponse{Status: http.StatusNotFound, Message: "error", Data: &fiber.Map{"data": "Member with specified ID not found!"}},
		)
	}

	return c.Status(http.StatusOK).JSON(
		responses.DendaResponse{Status: http.StatusOK, Message: "success", Data: &fiber.Map{"data": "Denda successfully deleted!"}},
	)
}

// fungsi untuk mengedit/update denda
func EditADenda(c *fiber.Ctx) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	dendaId := c.Params("dendaId")
	groupRefKey := c.Params("groupRefKey")
	var denda models.Denda
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

	objId, _ := primitive.ObjectIDFromHex(dendaId)

	if err := c.BodyParser(&denda); err != nil {
		return c.Status(http.StatusBadRequest).JSON(responses.DendaResponse{Status: http.StatusBadRequest, Message: "error", Data: &fiber.Map{"data": err.Error()}})
	}

	if validationErr := dendaValidate.Struct(&denda); validationErr != nil {
		return c.Status(http.StatusBadRequest).JSON(responses.DendaResponse{Status: http.StatusBadRequest, Message: "error", Data: &fiber.Map{"data": validationErr.Error()}})
	}

	update := bson.M{"title": denda.Title, "hari": denda.Hari, "nominal": denda.Nominal, "desc": denda.Desc}

	result, err := dendaCollection.UpdateOne(ctx, bson.M{"_id": objId}, bson.M{"$set": update})

	if err != nil {
		return c.Status(http.StatusInternalServerError).JSON(responses.DendaResponse{Status: http.StatusInternalServerError, Message: "error", Data: &fiber.Map{"data": err.Error()}})
	}

	var updatedDenda models.Denda
	if result.MatchedCount == 1 {
		err := dendaCollection.FindOne(ctx, bson.M{"_id": objId}).Decode(&updatedDenda)

		if err != nil {
			return c.Status(http.StatusInternalServerError).JSON(responses.DendaResponse{Status: http.StatusInternalServerError, Message: "error", Data: &fiber.Map{"data": err.Error()}})
		}
	}

	return c.Status(http.StatusOK).JSON(responses.DendaResponse{Status: http.StatusOK, Message: "success", Data: &fiber.Map{"data": updatedDenda}})
}

// fungsi membayar denda dengan file processing namun tidak bisa dilakukan di hostingan railway yang gratis
// api request harus menggunakan content type multipart/form-data
// func PayDenda(c *fiber.Ctx) error {
// 	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
// 	defer cancel()

// 	type PaymentRequest struct {
// 		ID primitive.ObjectID `form:"id_denda"`
// 	}

// 	var paymentRequest PaymentRequest
// 	if err := c.BodyParser(&paymentRequest); err != nil {
// 		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"message": "Failed to parse the JSON data"})
// 	}

// 	if err := Validate.Struct(paymentRequest); err != nil {
// 		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"message": err.Error()})
// 	}

// 	var denda models.Denda
// 	err := dendaCollection.FindOne(ctx, bson.M{"_id": paymentRequest.ID}).Decode(&denda)

// 	if err != nil {
// 		if err == mongo.ErrNoDocuments {
// 			return c.Status(http.StatusNotFound).JSON(responses.DendaResponse{
// 				Status:  http.StatusNotFound,
// 				Message: "Denda not found",
// 				Data:    nil,
// 			})
// 		}

// 		return c.Status(http.StatusInternalServerError).JSON(responses.DendaResponse{
// 			Status:  http.StatusInternalServerError,
// 			Message: "Error retrieving denda",
// 			Data:    &fiber.Map{"data": err.Error()},
// 		})
// 	}

// mengambil file pada request body
// 	file, err := c.FormFile("file")
// 	if err != nil {
// 		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"message": "No file detected"})
// 	}

// berfungsi seperti file open pada C, untuk membaca file
// 	// fileContent, err := file.Open()
// 	// if err != nil {
// 	// 	return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"message": "Failed to open the file"})
// 	// }
// 	// defer fileContent.Close()

// menentukan path penyimpanan file
// 	// filePath := fmt.Sprintf("./uploads/dendas/%s", file.Filename)

// menyimpan file
// 	// if err := c.SaveFile(file, filePath); err != nil {
// 	// 	return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"message": "Failed to save the uploaded file"})
// 	// }

// update status pembayaran
// 	filter := bson.M{"_id": paymentRequest.ID}
// 	update := bson.M{"$set": bson.M{"is_paid": true, "path": filepath}}
// 	_, err = dendaCollection.UpdateOne(ctx, filter, update)
// 	if err != nil {
// 		return c.Status(http.StatusInternalServerError).JSON(responses.DendaResponse{
// 			Status:  http.StatusInternalServerError,
// 			Message: "Failed to update denda payment status",
// 			Data:    &fiber.Map{"error": err.Error()},
// 		})
// 	}

// 	return c.Status(http.StatusOK).JSON(responses.DendaResponse{
// 		Status:  http.StatusOK,
// 		Message: "Denda payment successful",
// 		Data:    &fiber.Map{"dendaId": paymentRequest.ID},
// 	})
// }

// fungsi untuk membayar denda dengan link google drive
func PayDenda(c *fiber.Ctx) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	type PaymentRequest struct {
		ID   primitive.ObjectID `form:"id_denda"`
		Link string             `form:"file"`
	}

	var paymentRequest PaymentRequest
	if err := c.BodyParser(&paymentRequest); err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"message": "Failed to parse the form data"})
	}

	if err := Validate.Struct(paymentRequest); err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"message": err.Error()})
	}

	var denda models.Denda
	err := dendaCollection.FindOne(ctx, bson.M{"_id": paymentRequest.ID}).Decode(&denda)

	if err != nil {
		if err == mongo.ErrNoDocuments {
			return c.Status(http.StatusNotFound).JSON(responses.DendaResponse{
				Status:  http.StatusNotFound,
				Message: "Denda not found",
				Data:    nil,
			})
		}

		return c.Status(http.StatusInternalServerError).JSON(responses.DendaResponse{
			Status:  http.StatusInternalServerError,
			Message: "Error retrieving denda",
			Data:    &fiber.Map{"data": err.Error()},
		})
	}

	if paymentRequest.Link != "" {
		filter := bson.M{"_id": paymentRequest.ID}
		update := bson.M{"$set": bson.M{"is_paid": true, "link": paymentRequest.Link}}
		_, err = dendaCollection.UpdateOne(ctx, filter, update)
		if err != nil {
			return c.Status(http.StatusInternalServerError).JSON(responses.DendaResponse{
				Status:  http.StatusInternalServerError,
				Message: "Failed to update denda payment status",
				Data:    &fiber.Map{"error": err.Error()},
			})
		}

		return c.Status(http.StatusOK).JSON(responses.DendaResponse{
			Status:  http.StatusOK,
			Message: "Denda payment successful",
			Data:    &fiber.Map{"dendaId": paymentRequest.ID},
		})
	} else {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"message": "Google Drive link is required"})
	}
}

// fungsi untuk mengambil semua denda seorang member di group tertentu
func GetAllDenda(c *fiber.Ctx) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	memberID := c.Params("memberID")
	groupID := c.Params("groupID")

	objMemberID, err := primitive.ObjectIDFromHex(memberID)
	if err != nil {
		return c.Status(http.StatusBadRequest).JSON(responses.DendaResponse{
			Status:  http.StatusBadRequest,
			Message: "Invalid member ID",
		})
	}

	objGroupID, err := primitive.ObjectIDFromHex(groupID)
	if err != nil {
		return c.Status(http.StatusBadRequest).JSON(responses.DendaResponse{
			Status:  http.StatusBadRequest,
			Message: "Invalid group ID",
		})
	}

	filter := bson.M{"id_member": objMemberID, "id_group": objGroupID}

	cursor, err := dendaCollection.Find(ctx, filter)
	if err != nil {
		return c.Status(http.StatusInternalServerError).JSON(responses.DendaResponse{
			Status:  http.StatusInternalServerError,
			Message: "Error finding dendas",
		})
	}
	defer cursor.Close(ctx)

	var dendas []models.Denda
	if err := cursor.All(ctx, &dendas); err != nil {
		return c.Status(http.StatusInternalServerError).JSON(responses.DendaResponse{
			Status:  http.StatusInternalServerError,
			Message: "Error decoding dendas",
		})
	}

	return c.Status(http.StatusOK).JSON(responses.DendaResponse{
		Status:  http.StatusOK,
		Message: "Success",
		Data:    &fiber.Map{"dendas": dendas},
	})
}

func GetDenda(c *fiber.Ctx) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var denda models.Denda

	dendaID := c.Params("dendaID")

	objDendaID, err := primitive.ObjectIDFromHex(dendaID)
	if err != nil {
		return c.Status(http.StatusBadRequest).JSON(responses.DendaResponse{
			Status:  http.StatusBadRequest,
			Message: "Invalid denda ID",
		})
	}
	err = dendaCollection.FindOne(ctx, bson.M{"_id": objDendaID}).Decode(&denda)

	if err != nil {
		return c.Status(http.StatusInternalServerError).JSON(responses.DendaResponse{
			Status:  http.StatusInternalServerError,
			Message: "Error finding denda",
		})
	}

	return c.Status(http.StatusOK).JSON(responses.DendaResponse{
		Status:  http.StatusOK,
		Message: "Success",
		Data:    &fiber.Map{"data": denda},
	})
}

// fungsi untuk menampilakn semua denda yang sudah dibayar dari seorang member pada group tertentu
func GetPaidDenda(c *fiber.Ctx) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	memberID := c.Params("memberID")
	groupID := c.Params("groupID")

	objMemberID, err := primitive.ObjectIDFromHex(memberID)
	if err != nil {
		return c.Status(http.StatusBadRequest).JSON(responses.DendaResponse{
			Status:  http.StatusBadRequest,
			Message: "Invalid member ID",
		})
	}

	objGroupID, err := primitive.ObjectIDFromHex(groupID)
	if err != nil {
		return c.Status(http.StatusBadRequest).JSON(responses.DendaResponse{
			Status:  http.StatusBadRequest,
			Message: "Invalid group ID",
		})
	}

	filter := bson.M{"id_member": objMemberID, "id_group": objGroupID, "is_paid": true}

	cursor, err := dendaCollection.Find(ctx, filter)
	if err != nil {
		return c.Status(http.StatusInternalServerError).JSON(responses.DendaResponse{
			Status:  http.StatusInternalServerError,
			Message: "Error finding dendas",
		})
	}
	defer cursor.Close(ctx)

	var dendas []models.Denda
	if err := cursor.All(ctx, &dendas); err != nil {
		return c.Status(http.StatusInternalServerError).JSON(responses.DendaResponse{
			Status:  http.StatusInternalServerError,
			Message: "Error decoding dendas",
		})
	}

	return c.Status(http.StatusOK).JSON(responses.DendaResponse{
		Status:  http.StatusOK,
		Message: "Success",
		Data:    &fiber.Map{"dendas": dendas},
	})
}

// fungsi untuk menampilakn semua denda yang belum dibayar dari seorang member pada group tertentu
func GetUnPaidDenda(c *fiber.Ctx) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	memberID := c.Params("memberID")
	groupID := c.Params("groupID")

	objMemberID, err := primitive.ObjectIDFromHex(memberID)
	if err != nil {
		return c.Status(http.StatusBadRequest).JSON(responses.DendaResponse{
			Status:  http.StatusBadRequest,
			Message: "Invalid member ID",
		})
	}

	objGroupID, err := primitive.ObjectIDFromHex(groupID)
	if err != nil {
		return c.Status(http.StatusBadRequest).JSON(responses.DendaResponse{
			Status:  http.StatusBadRequest,
			Message: "Invalid group ID",
		})
	}

	filter := bson.M{"id_member": objMemberID, "id_group": objGroupID, "is_paid": false}

	cursor, err := dendaCollection.Find(ctx, filter)
	if err != nil {
		return c.Status(http.StatusInternalServerError).JSON(responses.DendaResponse{
			Status:  http.StatusInternalServerError,
			Message: "Error finding dendas",
		})
	}
	defer cursor.Close(ctx)

	var dendas []models.Denda
	if err := cursor.All(ctx, &dendas); err != nil {
		return c.Status(http.StatusInternalServerError).JSON(responses.DendaResponse{
			Status:  http.StatusInternalServerError,
			Message: "Error decoding dendas",
		})
	}

	return c.Status(http.StatusOK).JSON(responses.DendaResponse{
		Status:  http.StatusOK,
		Message: "Success",
		Data:    &fiber.Map{"dendas": dendas},
	})
}
