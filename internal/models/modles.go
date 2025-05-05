package models

import "time"

type (
	User struct {
		ID           string    `gorm:"primaryKey;type:uuid;default:uuid_generate_v4()"`
		FullName     string    `gorm:"not null"`
		Username     string    `gorm:"unique;not null"`
		PasswordHash string    `gorm:"not null"`
		CreatedAt    time.Time `gorm:"autoCreateTime"`
	}

	RefreshToken struct {
		ID         string    `gorm:"primaryKey;type:uuid;default:uuid_generate_v4()"`
		UserID     string    `gorm:"type:uuid;not null;index"`
		TokenHash  string    `gorm:"not null"`
		DeviceID   string    `gorm:"not null"`
		CreatedAt  time.Time `gorm:"autoCreateTime"`
		ExpiresAt  time.Time `gorm:"not null"`
		LastUsedAt time.Time
	}
)
