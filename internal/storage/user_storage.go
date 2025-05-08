package storage

import (
	"context"
	"errors"

	"github.com/ruziba3vich/mm_user_service/internal/models"
	"gorm.io/gorm"
)

type UserStorage struct {
	db *gorm.DB
}

func (r *UserStorage) getCurrentProfilePicURL(ctx context.Context, userID string) (string, error) {
	var pic models.ProfilePicture

	err := r.db.WithContext(ctx).
		Where("user_id = ?", userID).
		Order("created_at DESC").
		First(&pic).Error

	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return "", nil
		}
		return "", err
	}
	return pic.FileName, nil
}
