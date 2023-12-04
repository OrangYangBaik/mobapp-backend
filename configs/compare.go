package configs

import "golang.org/x/crypto/bcrypt"

// ComparePasswords compares a hashed password with its plaintext version
func ComparePasswords(hashedPassword, password string) error {
	return bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
}
