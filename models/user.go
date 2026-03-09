package models

import "gorm.io/gorm"

type User struct {
	gorm.Model
	Username           string `gorm:"uniqueIndex;not null"`
	PasswordHash       string `gorm:"not null"`
	ParentPasswordHash string // Master vault password
	TOTPSecret         string // Empty if TOTP is not set up
}
