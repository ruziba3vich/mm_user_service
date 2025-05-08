package storage

import (
	"context"
	"database/sql"
	"errors"
	"strings"

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

func (s *UserStorage) CheckUserAFollowsUserB(ctx context.Context, userA, userB string) (bool, error) {
	if userA == "" || userB == "" {
		return false, errors.New("both user IDs are required")
	}

	if userA == userB {
		return false, errors.New("cannot check if user follows themselves")
	} // TODO: this part should be in service layer

	var following models.Followings
	err := s.db.WithContext(ctx).
		Where("follower = ? AND following = ?", userA, userB).
		First(&following).
		Error

	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return false, nil
		}
		return false, err
	}

	return true, nil
}

func (s *UserStorage) FollowUserBByUserA(ctx context.Context, userA, userB, generatedID string) error {
	const maxRetries = 3 // TODO: get this value from config

	for i := range maxRetries {
		err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
			if userA == "" || userB == "" {
				return errors.New("both user IDs are required")
			}
			if userA == userB {
				return errors.New("user cannot follow themselves")
			}

			var targetUser models.User
			if err := tx.Select("id").First(&targetUser, "id = ?", userB).Error; err != nil {
				if errors.Is(err, gorm.ErrRecordNotFound) {
					return errors.New("target user not found")
				}
				return err
			}

			var existingFollow models.Followings
			err := tx.Where("follower = ? AND following = ?", userA, userB).
				First(&existingFollow).Error
			if err == nil {
				return errors.New("already following this user")
			}
			if !errors.Is(err, gorm.ErrRecordNotFound) {
				return err
			} // TODO: use CheckUserAFollowsUserB instead, and move this into service layer

			var userAInfo models.User
			if err := tx.Select("following_version").
				Where("id = ?", userA).
				First(&userAInfo).Error; err != nil {
				return err
			}
			expectedVersion := userAInfo.FollowingVersion

			newFollow := models.Followings{
				ID:        generatedID,
				Follower:  userA,
				Following: userB,
			}
			if err := tx.Create(&newFollow).Error; err != nil {
				if isDuplicateKeyError(err) {
					return errors.New("follow relationship already exists")
				}
				return err
			}

			result := tx.Model(&models.User{}).
				Where("id = ? AND following_version = ?", userA, expectedVersion).
				Update("following_version", gorm.Expr("following_version + 1"))

			if result.RowsAffected == 0 {
				return errors.New("version conflict")
			}

			if err := tx.Model(&models.User{}).
				Where("id = ?", userB).
				Update("followers_count", gorm.Expr("followers_count + 1")).Error; err != nil {
				return err
			}

			return nil
		}, &sql.TxOptions{
			Isolation: sql.LevelReadCommitted,
			ReadOnly:  false,
		})

		if err == nil {
			return nil
		}
		if err.Error() == "version conflict" && i < maxRetries {
			continue
		}
		return err
	}

	return errors.New("failed to follow user after multiple retries due to version conflicts")
}

func isDuplicateKeyError(err error) bool {
	return strings.Contains(err.Error(), "duplicate key") ||
		strings.Contains(err.Error(), "23505")
}
