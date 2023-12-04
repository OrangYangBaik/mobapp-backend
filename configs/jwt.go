package configs

import (
	"os"
)

var JWTSecretKey = getJWTSecretKey()

func getJWTSecretKey() string {
	secretKey := os.Getenv("JWT_SECRET_KEY")

	return secretKey
}
