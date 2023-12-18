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

// untuk menargetkan collection members di database
var memberCollection *mongo.Collection = configs.GetCollection(configs.DB, "members")

// custom validation untuk member
var memberValidate = validator.New()

// default validation
var Validate = validator.New()

// fungsi untuk hash passowrd
func hashPassword(password string) (string, error) {
	// password hashing dengan bcrypt
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	// return string hasil hash password
	return string(hashedPassword), nil
}

// fungsi untuk create member
func CreateMember(c *fiber.Ctx) error {
	// berfungsi untuk memberikan timeout pada operasi yang mungkin akan memakan waktu, time out diberikan sebesar 10 detik
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)

	// mengaktifkan fungsi cancel untuk operasi yang melebihi 10 detik
	defer cancel()

	//initialisasi member dengan model Member
	var member models.Member

	// json request body akan di parse/dimasukkan ke struct member
	if err := c.BodyParser(&member); err != nil {
		return c.Status(http.StatusBadRequest).JSON(responses.MemberResponse{
			Status:  http.StatusBadRequest,
			Message: "Failed to parse the request body",
			Data:    &fiber.Map{"error": err.Error()},
		})
	}

	// struct member akan di validasi dengan memberValidate (cek kolom yang diset "required")
	if validationErr := memberValidate.Struct(&member); validationErr != nil {
		return c.Status(http.StatusBadRequest).JSON(responses.MemberResponse{
			Status:  http.StatusBadRequest,
			Message: "Validation failed",
			Data:    &fiber.Map{"error": validationErr.Error()},
		})
	}

	//mengakses atribut Password dari struct member
	password := member.Password
	hashedPassword, err := hashPassword(password)

	//jika err berisikan value
	if err != nil {
		return c.Status(http.StatusInternalServerError).JSON(responses.MemberResponse{
			Status:  http.StatusInternalServerError,
			Message: "Failed to hash the password",
			Data:    &fiber.Map{"error": err.Error()},
		})
	}

	//membuat struct baru untuk dimasukkan ke database (bisa juga langsung menggunakan struct member yang sudah ada)
	newMember := models.Member{
		ID:       primitive.NewObjectID(),
		Nama:     member.Nama,
		NIM:      member.NIM,
		Password: hashedPassword,
		Email:    member.Email,
		Prodi:    member.Prodi,
		Angkatan: member.Angkatan,
	}

	//memasukkan struct newMember ke database
	_, err = memberCollection.InsertOne(ctx, newMember)
	if err != nil {
		return c.Status(http.StatusInternalServerError).JSON(responses.MemberResponse{
			Status:  http.StatusInternalServerError,
			Message: "Failed to insert member",
			Data:    &fiber.Map{"error": err.Error()},
		})
	}

	//return successful response
	return c.Status(http.StatusCreated).JSON(responses.MemberResponse{
		Status:  http.StatusCreated,
		Message: "Member created successfully",
		Data:    &fiber.Map{"member email": newMember.Email},
	})
}

// fungsi untuk login user
func LoginMember(c *fiber.Ctx) error {
	// berfungsi untuk memberikan timeout pada operasi yang mungkin akan memakan waktu, time out diberikan sebesar 10 detik
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	// mengaktifkan fungsi cancel untuk operasi yang melebihi 10 detik
	defer cancel()

	// initialisasi struct untuk memasukkan request body ke struct LoginRequest
	type LoginRequest struct {
		Email    string `json:"email" form:"email" validate:"required,email"`
		Password string `json:"password" form:"password" validate:"required"`
	}

	//initialisasi loginRequest dengan struct LoginRequest
	var loginRequest LoginRequest

	// request body diparse ke struct loginRequest
	if err := c.BodyParser(&loginRequest); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"message": "Failed to parse the request body"})
	}

	// validasi isi loginRequest dengan memberValidation
	if err := memberValidate.Struct(loginRequest); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"message": err.Error()})
	}

	var member models.Member

	//search data di database dengan kondisi email == loginRequest.Email lalu di decode/dimasukkan ke struct member
	err := memberCollection.FindOne(ctx, bson.M{"email": loginRequest.Email}).Decode(&member)
	if err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"message": "Invalid email or password 1"})
	}

	//komparasi password
	if err := configs.ComparePasswords(member.Password, loginRequest.Password); err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"message": "Invalid email or password 2"})
	}

	//inisialisasi token jwt
	token := jwt.New(jwt.SigningMethodHS256)

	//claims adalah untuk menyimpan current loggedin user
	claims := token.Claims.(jwt.MapClaims)

	//didalam claims akan tersimpan atribut sebagai berikut
	claims["id"] = member.ID.Hex()
	claims["nama"] = member.Nama
	claims["nim"] = member.NIM
	claims["email"] = member.Email
	claims["prodi"] = member.Prodi
	claims["angkatan"] = member.Angkatan
	claims["exp"] = time.Now().Add(time.Hour * 24).Unix() // token akan berakhir dalam 24 jam

	//proses generasi token
	tokenString, err := token.SignedString([]byte(configs.JWTSecretKey))
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"message": "Failed to generate JWT token"})
	}

	return c.JSON(fiber.Map{"message": "Login successful", "token": tokenString})
}

// fungsi untuk mengambil informasi current loggedin user
func GetProfile(c *fiber.Ctx) error {
	// mengambil current loggedin user
	user := c.Locals("user")
	return c.Status(http.StatusCreated).JSON(responses.GroupResponse{
		Status:  http.StatusCreated,
		Message: "Here is your profile",
		Data:    &fiber.Map{"profile": user},
	})
}

// fungsi untuk get sebuah member
func GetAMember(c *fiber.Ctx) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)

	// mengambil parameter
	memberId := c.Params("MemberId")
	groupRefKey := c.Params("groupRefKey")

	var member models.Member
	defer cancel()

	user := c.Locals("user")
	// proses pengambilan current loggedin user lalu dimasukkan ke dalam userClaims
	userClaims, ok := user.(jwt.MapClaims)
	if !ok {
		return c.Status(http.StatusInternalServerError).JSON(responses.GroupResponse{
			Status:  http.StatusInternalServerError,
			Message: "Failed to get user claims from context",
			Data:    &fiber.Map{"error": "user claims not found or not a MapClaims"},
		})
	}

	//mengakses userClaims id
	memberIDHex, ok := userClaims["id"].(string)
	if !ok {
		return c.Status(http.StatusInternalServerError).JSON(responses.GroupResponse{
			Status:  http.StatusInternalServerError,
			Message: "Failed to get user ID from claims",
			Data:    &fiber.Map{"error": "user ID not found or not a string"},
		})
	}

	// cek apakah current user adalah admin di group
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

	// perubahan id dari string ke primitive.ObjectID
	objId, _ := primitive.ObjectIDFromHex(memberId)

	// cari data dengan kondisi id == objId lalu di decode ke struct member
	err = memberCollection.FindOne(ctx, bson.M{"_id": objId}).Decode(&member)
	if err != nil {
		return c.Status(http.StatusInternalServerError).JSON(responses.MemberResponse{Status: http.StatusInternalServerError, Message: "error", Data: &fiber.Map{"data": err.Error()}})
	}

	return c.Status(http.StatusOK).JSON(responses.MemberResponse{Status: http.StatusOK, Message: "success", Data: &fiber.Map{"data": member}})
}

// fungsi untuk edit informasi member/user
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
	// setup atribut apa saja yang akan di edit/update
	update := bson.M{"nama": member.Nama, "nim": member.NIM, "password": hashedPassword, "email": member.Email, "prodi": member.Prodi, "angkatan": member.Angkatan}

	// proses update dengan kondisi id == objId lalu data akan diupdate sesuai dengan setup
	result, err := memberCollection.UpdateOne(ctx, bson.M{"_id": objId}, bson.M{"$set": update})

	if err != nil {
		return c.Status(http.StatusInternalServerError).JSON(responses.MemberResponse{Status: http.StatusInternalServerError, Message: "error", Data: &fiber.Map{"data": err.Error()}})
	}

	var updatedMember models.Member
	// pengecekan apakah data ditemukan dan berhasil di update
	if result.MatchedCount == 1 && result.ModifiedCount == 1 {
		err := memberCollection.FindOne(ctx, bson.M{"_id": objId}).Decode(&updatedMember)

		if err != nil {
			return c.Status(http.StatusInternalServerError).JSON(responses.MemberResponse{Status: http.StatusInternalServerError, Message: "error", Data: &fiber.Map{"data": err.Error()}})
		}

		return c.Status(http.StatusOK).JSON(responses.MemberResponse{Status: http.StatusOK, Message: "success"})

	} else {
		return c.Status(http.StatusNotFound).JSON(responses.MemberResponse{Status: http.StatusNotFound, Message: "Document not found or not modified", Data: nil})
	}
}

// fungsi untuk delete member atau user
func DeleteAMember(c *fiber.Ctx) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	memberId := c.Params("memberId")
	defer cancel()

	objId, _ := primitive.ObjectIDFromHex(memberId)

	// proses penghapusan data di memberCollection dengan kondisi id == objId
	result, err := memberCollection.DeleteOne(ctx, bson.M{"_id": objId})
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

// fungsi untuk cek apakah current user admin di group tersebut atau tidak
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
	// mengembalikan keterangan apakah current loggedin user adalah admin atau tidak
	return membership.IsAdmin, nil
}

// fungsi untuk cek apakah current user admin atau bukan di sebuah group
func IsAdmin(c *fiber.Ctx) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	groupRefKey := c.Params("groupRefKey")

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

	return c.Status(http.StatusOK).JSON(fiber.Map{"isAdmin": isAdmin})
}

// get semua member dalam sebuah group
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

	// proses pengambilan data dengan kondisi id_group == group.ID && is_allowed == true
	cursor, err := membershipCollection.Find(ctx, bson.M{"id_group": group.ID, "is_allowed": true})
	if err != nil {
		return c.Status(http.StatusInternalServerError).JSON(responses.GroupResponse{
			Status:  http.StatusInternalServerError,
			Message: "Error retrieving memberships",
			Data:    &fiber.Map{"data": err.Error()},
		})
	}
	defer cursor.Close(ctx)

	// memasukkan data yang didapat ke array of struct membership
	if err := cursor.All(ctx, &memberships); err != nil {
		return c.Status(http.StatusInternalServerError).JSON(responses.GroupResponse{
			Status:  http.StatusInternalServerError,
			Message: "Error decoding memberships",
			Data:    &fiber.Map{"data": err.Error()},
		})
	}

	// iterasi setiap membership, dapatkan member di memberCollection lalu masukkan ke array members
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

// menghapus membership dalam grorup
func KickAMember(c *fiber.Ctx) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	type KickRequest struct {
		GroupRefKey      string `json:"groupRefKey" form:"string" validate:"required"`
		MemberToBeKicked string `json:"memberID" form:"string" validate:"required"`
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

	// proses delete pada satu document dengan kondisi id_group dan id_member
	result, err := membershipCollection.DeleteOne(ctx, bson.M{"id_group": group.ID, "id_member": memberToBeKickedID})
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return c.Status(http.StatusNotFound).JSON(responses.GroupResponse{
				Status:  http.StatusNotFound,
				Message: "Membership not found",
			})
		}
	}

	// cek apakah terdapat document yang terdelete
	if result.DeletedCount < 1 {
		return c.Status(http.StatusNotFound).JSON(
			responses.GroupResponse{Status: http.StatusNotFound, Message: "error", Data: &fiber.Map{"data": "Membership with specified ID not found!"}},
		)
	}

	return c.Status(http.StatusOK).JSON(
		responses.GroupResponse{Status: http.StatusOK, Message: "success", Data: &fiber.Map{"data": "Member successfully kicked!"}},
	)
}

// fungsi untuk berikan status admin
func GiveAdmin(c *fiber.Ctx) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	type GiveAdminRequest struct {
		GroupRefKey     string `json:"groupRefKey" form:"string" validate:"required"`
		MemberToBeAdmin string `json:"memberID" form:"string" validate:"required"`
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

	//proses pemberian admin pada member
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

	// cek apakah terdapat member dengan id_member dan id_group tersebut
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

// fungsi untuk mengambil status admin
func RevokeAdmin(c *fiber.Ctx) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	type RevokeAdminRequest struct {
		GroupRefKey       string `json:"groupRefKey" form:"string" validate:"required"`
		MemberToBeRevoked string `json:"memberID" form:"string" validate:"required"`
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

	var revokeAdminReq RevokeAdminRequest
	if err := c.BodyParser(&revokeAdminReq); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"message": "Failed to parse the request body"})
	}

	if err := Validate.Struct(revokeAdminReq); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"message": err.Error()})
	}

	//cek apakah user admin atau tidak pada group tersebut
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

	// proses pengantian admin memjadi non admin
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

// fungsi untuk validasi member yang request join ke sebuh group oleh admin group
func AccMember(c *fiber.Ctx) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	type JoinGroupRequest struct {
		GroupRefKey string `json:"groupRefKey" validate:"required"`
		ReqMemberID string `json:"memberID" validate:"required"`
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

	var joinGroupReq JoinGroupRequest
	if err := c.BodyParser(&joinGroupReq); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"message": "Failed to parse the request body"})
	}

	if err := Validate.Struct(joinGroupReq); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"message": err.Error()})
	}

	isAdmin, err := checkAdmin(ctx, memberIDHex, joinGroupReq.GroupRefKey)
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
	err = groupCollection.FindOne(ctx, bson.M{"refkey": joinGroupReq.GroupRefKey}).Decode(&group)
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

	// approve member yang akan masuk oleh admin
	update := bson.M{"is_allowed": true}
	memberJoin, err := primitive.ObjectIDFromHex(joinGroupReq.ReqMemberID)
	result, err := membershipCollection.UpdateOne(
		ctx,
		bson.M{"id_member": memberJoin, "id_group": group.ID},
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
