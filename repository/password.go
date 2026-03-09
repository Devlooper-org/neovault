package repository

import (
	"github.com/jigarvarma2k20/neovault/database"
	"github.com/jigarvarma2k20/neovault/models"
)

func CreatePasswordEntry(entry *models.PasswordEntry) error {
	return database.DB.Create(entry).Error
}

func GetPasswordEntriesByUserID(userID uint) ([]models.PasswordEntry, error) {
	var entries []models.PasswordEntry
	if err := database.DB.Where("user_id = ?", userID).Find(&entries).Error; err != nil {
		return nil, err
	}
	return entries, nil
}

func GetPasswordEntryByIDAndUserID(id string, userID uint) (*models.PasswordEntry, error) {
	var entry models.PasswordEntry
	if err := database.DB.Where("id = ? AND user_id = ?", id, userID).First(&entry).Error; err != nil {
		return nil, err
	}
	return &entry, nil
}

func DeletePasswordEntry(id string, userID uint) error {
	return database.DB.Where("id = ? AND user_id = ?", id, userID).Delete(&models.PasswordEntry{}).Error
}
