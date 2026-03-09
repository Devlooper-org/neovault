package database

import (
	"log"
	"github.com/jigarvarma2k20/neovault/models"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

var DB *gorm.DB

func ConnectDB(dsn string) {
	var err error
	DB, err = gorm.Open(postgres.New(postgres.Config{
		DSN:                  dsn,
		PreferSimpleProtocol: true, // disables implicit prepared statement usage to fix cache errors
	}), &gorm.Config{})
	if err != nil {
		log.Fatal("Failed to connect to database. \n", err)
	}

	log.Println("Database connected")

	// Auto-migrate models
	err = DB.AutoMigrate(&models.User{}, &models.PasswordEntry{})
	if err != nil {
		log.Fatal("Failed to migrate database. \n", err)
	}

	log.Println("Database migrated")
}
