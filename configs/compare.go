package configs

import "golang.org/x/crypto/bcrypt"

// komparasi pass dari datbes sama yang diinput user
func ComparePasswords(hashedPassword, password string) error {
	return bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
}
