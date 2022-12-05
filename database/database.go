package database

import (
	"log"
	"os"

	"github.com/kwmekyeimonies/go-jwt-auth/models"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

var DB *gorm.DB

func Connect_Database() {
	db, err := gorm.Open(postgres.Open(os.Getenv("POSTGRES_URL")), &gorm.Config{})

	if err != nil {
		log.Fatal(err)
	}

	db.AutoMigrate(&models.User{})

	DB = db

}
