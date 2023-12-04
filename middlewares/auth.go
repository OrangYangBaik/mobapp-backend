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
		// Get the "Authorization" header from the request
		authHeader := c.Get("Authorization")

		// Check if the header is missing or doesn't start with "Bearer "
		if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"message": "Unauthorized"})
		}

		// Extract the JWT token from the header
		tokenString := strings.TrimPrefix(authHeader, "Bearer ")

		// Parse and validate the JWT token
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			// Check the signing method
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("Invalid signing method")
			}
			// Provide the key for validation
			return []byte(configs.JWTSecretKey), nil
		})

		// Check for errors during parsing or validation
		if err != nil || !token.Valid {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"message": "Unauthorized"})
		}

		// Set the user information in the context for further handling
		c.Locals("user", token.Claims.(jwt.MapClaims))
		//fmt.Println(c.Locals("user").(jwt.MapClaims))
		// Continue to the next middleware or route handler
		return c.Next()
	}
}
