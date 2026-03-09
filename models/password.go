package models

import "gorm.io/gorm"

type PasswordEntry struct {
	gorm.Model
	UserID            uint   `gorm:"not null;index"`
	Website           string `gorm:"not null"`
	WebsiteUsername   string `gorm:"not null"`
	EncryptedPassword string `gorm:"not null"` // encrypted with master key
	TOTPSecret        string `gorm:"not null"` // per-credential 2fa
}
