package storage

import (
	"github.com/ruziba3vich/mm_article_service/pkg/config"
	"github.com/ruziba3vich/mm_user_service/internal/models"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

// NewGORM initializes a GORM database connection with migrations
func NewGORM(cfg *config.Config) (*gorm.DB, error) {
	db, err := gorm.Open(postgres.Open(cfg.PsqlCfg.Dsn), &gorm.Config{})
	if err != nil {
		return nil, err
	}
	err = db.AutoMigrate(&models.User{}, &models.ProfilePicture{}, &models.Followings{}, &models.RefreshToken{})
	if err != nil {
		return nil, err
	}
	return db, nil
}
