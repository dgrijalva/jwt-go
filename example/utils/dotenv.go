package util

import (
	"os"

	"github.com/joho/godotenv"
)

func GodotEnv(key string) string {
	os.Setenv("GO_ENV", "development")
	env := make(chan string, 1)

	if os.Getenv("GO_ENV") != "production" {
		godotenv.Load(".env")
		env <- os.Getenv(key)
	}

	return <-env
}
