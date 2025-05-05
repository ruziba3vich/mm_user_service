package models

import "time"

type User struct {
	ID           string    `gorm:"primaryKey;type:uuid;default:uuid_generate_v4()"`
	Username     string    `gorm:"unique;not null"`
	PasswordHash string    `gorm:"not null"`
	CreatedAt    time.Time `gorm:"autoCreateTime"`
}
