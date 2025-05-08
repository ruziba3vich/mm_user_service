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

func NewUserStorage(db *gorm.DB) *UserStorage {
	return &UserStorage{
		db: db,
	}
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

func (s *UserStorage) CreateUser(ctx context.Context, user *models.User) (*models.User, error) {
	if user == nil {
		return nil, errors.New("user cannot be nil")
	}

	if user.FullName == "" || user.Username == "" || user.PasswordHash == "" {
		return nil, errors.New("full name, username, and password hash are required")
	} // TODO: this part should be in service layer

	err := s.db.WithContext(ctx).Create(user).Error
	if err != nil {
		if errors.Is(err, gorm.ErrDuplicatedKey) {
			return nil, errors.New("username already exists")
		}
		return nil, err
	}

	return user, nil
}

func (s *UserStorage) ValidateUserCredentials(ctx context.Context, username, passwordHash string) (*models.User, error) {
	if username == "" || passwordHash == "" {
		return nil, errors.New("username and password hash are required")
	} // TODO: this part should be in service layer

	var user models.User
	err := s.db.WithContext(ctx).
		Where("username = ? AND password_hash = ?", username, passwordHash).
		First(&user).
		Error

	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, errors.New("invalid credentials")
		}
		return nil, err
	}

	return &user, nil
}

func (s *UserStorage) AddProfilePicture(ctx context.Context, userId string, fileName string, pictureId string) error {
	if userId == "" || fileName == "" || pictureId == "" {
		return errors.New("userId, fileName, and pictureId are required")
	} // TODO: this part should be in service layer

	profilePic := models.ProfilePicture{
		ID:       pictureId,
		FileName: fileName,
		UserID:   userId,
	}

	return s.db.WithContext(ctx).Create(&profilePic).Error
}

func (s *UserStorage) RemoveProfilePicture(ctx context.Context, userId, fileName string) error {
	if userId == "" || fileName == "" {
		return errors.New("userId and fileName are required")
	}

	result := s.db.WithContext(ctx).
		Where("user_id = ? AND file_name = ?", userId, fileName).
		Delete(&models.ProfilePicture{})

	if result.Error != nil {
		return result.Error
	}

	if result.RowsAffected == 0 {
		return errors.New("profile picture not found")
	}

	return nil
}

func (s *UserStorage) UpdateUser(ctx context.Context, filter map[string]any) (*models.User, error) {
	if len(filter) == 0 {
		return nil, errors.New("empty filter provided")
	}

	// Extract user ID from filter (required for update)
	userId, ok := filter["id"].(string)
	if !ok || userId == "" {
		return nil, errors.New("user id is required in filter")
	}

	// Remove id from update fields since we don't want to update it
	updateFields := make(map[string]any)
	for k, v := range filter {
		if k != "id" {
			updateFields[k] = v
		}
	}

	if len(updateFields) == 0 {
		return nil, errors.New("no valid fields to update")
	} // TODO: the logi should be in service layer

	var user models.User
	err := s.db.WithContext(ctx).
		Model(&user).
		Where("id = ?", userId).
		Updates(updateFields).
		First(&user).Error

	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, errors.New("user not found")
		}
		return nil, err
	}

	return &user, nil
}

func (s *UserStorage) GetUserById(ctx context.Context, userID string) (*models.User, error) {
	if userID == "" {
		return nil, errors.New("user ID is required")
	} // TODO: this part should be in service layer

	var user models.User
	err := s.db.WithContext(ctx).
		Where("id = ?", userID).
		First(&user).
		Error

	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, errors.New("user not found")
		}
		return nil, err
	}

	return &user, nil
}

func (s *UserStorage) GetUserProfilePics(ctx context.Context, userID string) ([]*models.ProfilePicture, error) {
	if userID == "" {
		return nil, errors.New("user ID is required")
	} // TODO: this part should be in service layer

	var pictures []*models.ProfilePicture
	err := s.db.WithContext(ctx).
		Where("user_id = ?", userID).
		Order("created_at DESC").
		Find(&pictures).
		Error

	if err != nil {
		return nil, err
	}

	return pictures, nil
}

func (s *UserStorage) CheckUserAFollowsUserB(ctx context.Context, userA, userB string) error {
	if userA == "" || userB == "" {
		return errors.New("both user IDs are required")
	}

	if userA == userB {
		return errors.New("cannot check if user follows themselves")
	} // TODO: this part should be in service layer

	var following models.Followings
	err := s.db.WithContext(ctx).
		Where("follower = ? AND following = ?", userA, userB).
		First(&following).
		Error

	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return errors.New("user does not follow the target user")
		}
		return err
	}

	return nil
}
