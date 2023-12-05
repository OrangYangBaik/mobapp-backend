package middlewares

import (
	"fiber-mongo-api/configs"
	"fmt"
	"strings"

	"github.com/dgrijalva/jwt-go"
	"github.com/gofiber/fiber/v2"
)

func JWTMiddleware() func(*fiber.Ctx) error {
	return func(c *fiber.Ctx) error {
		//ambil header "atthorization"
		authHeader := c.Get("Authorization")

		// cek headernya kosong ato g ada prefix bearer
		if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"message": "Unauthorized"})
		}

		//ekstrak jwt tokennya
		tokenString := strings.TrimPrefix(authHeader, "Bearer ")

		// validasi tokennya
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			// cek signing method?
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("Invalid signing method")
			}
			// kirim keynya
			return []byte(configs.JWTSecretKey), nil
		})

		if err != nil || !token.Valid {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"message": "Unauthorized"})
		}

		// taro user di lokal kek auth user di laravel
		c.Locals("user", token.Claims.(jwt.MapClaims))
		//fmt.Println(c.Locals("user").(jwt.MapClaims))

		return c.Next()
	}
}
