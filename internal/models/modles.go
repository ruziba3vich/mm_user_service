package models

import "time"

type (
	User struct {
		ID               string    `gorm:"primaryKey;type:uuid"`
		FullName         string    `gorm:"not null"`
		Username         string    `gorm:"unique;not null"`
		PasswordHash     string    `gorm:"not null"`
		CreatedAt        time.Time `gorm:"autoCreateTime"`
		FollowersCount   int       `gorm:"default:0"`
		FollowingVersion uint      `gorm:"default:1"`
	}

	RefreshToken struct {
		ID         string    `gorm:"primaryKey"`
		UserID     string    `gorm:"type:uuid;not null;index"`
		TokenHash  string    `gorm:"not null"`
		DeviceID   string    `gorm:"not null"`
		CreatedAt  time.Time `gorm:"autoCreateTime"`
		ExpiresAt  time.Time `gorm:"not null"`
		LastUsedAt time.Time
	}

	ProfilePicture struct {
		ID        string    `gorm:"primaryKey;type:uuid"`
		FileName  string    `gorm:"not null"`
		UserID    string    `gorm:"type:uuid;not null;index"`
		CreatedAt time.Time `gorm:"autoCreateTime"`
	}

	Followings struct {
		ID        string `gorm:"primaryKey;type:uuid"`
		Following string `gorm:"type:uuid;not null;index"`
		Follower  string `gorm:"type:uuid;not null;index"`
	}
)
