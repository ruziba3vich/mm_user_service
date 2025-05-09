package storage

import (
	"context"
	"database/sql"
	"errors"
	"strings"

	"github.com/ruziba3vich/mm_user_service/internal/models"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
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
	result := s.db.WithContext(ctx).
		Where("user_id = ? AND file_name = ?", userId, fileName).
		Delete(&models.ProfilePicture{})

	if result.Error != nil {
		if errors.Is(gorm.ErrRecordNotFound, result.Error) {
			return status.Error(codes.NotFound, "profile picture not found")
		}
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

	userId, ok := filter["id"].(string)
	if !ok || userId == "" {
		return nil, errors.New("user id is required in filter")
	}

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
				return status.Error(codes.AlreadyExists, "already following this user")
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
					return status.Error(codes.AlreadyExists, "already following this user")
				}
				return err
			}

			result := tx.Model(&models.User{}).
				Where("id = ? AND following_version = ?", userA, expectedVersion).
				Update("following_version", gorm.Expr("following_version + 1"))

			if result.RowsAffected == 0 {
				return status.Error(codes.Internal, "version conflict")
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
		} // TODO: need to create a custom error and compare with it
		return err
	}

	return errors.New("failed to follow user after multiple retries due to version conflicts")
}

func (s *UserStorage) UnfollowUserBByUserA(ctx context.Context, userA, userB string) error {
	const maxRetries = 3 // TODO: get this value from config

	for i := 0; i < maxRetries; i++ {
		err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
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
			if err != nil {
				if errors.Is(err, gorm.ErrRecordNotFound) {
					return errors.New("not following this user")
				}
				return err
			}

			var userAInfo models.User
			if err := tx.Select("following_version").
				Where("id = ?", userA).
				First(&userAInfo).Error; err != nil {
				return err
			}
			expectedVersion := userAInfo.FollowingVersion

			result := tx.Where("follower = ? AND following = ?", userA, userB).
				Delete(&models.Followings{})
			if result.Error != nil {
				return result.Error
			}
			if result.RowsAffected == 0 {
				return errors.New("failed to delete follow relationship")
			}

			versionResult := tx.Model(&models.User{}).
				Where("id = ? AND following_version = ?", userA, expectedVersion).
				Update("following_version", gorm.Expr("following_version + 1"))
			if versionResult.RowsAffected == 0 {
				return errors.New("version conflict")
			}

			if err := tx.Model(&models.User{}).
				Where("id = ?", userB).
				Update("followers_count", gorm.Expr("followers_count - 1")).Error; err != nil {
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
	return errors.New("failed to unfollow user after multiple retries due to version conflicts")
}

func isDuplicateKeyError(err error) bool {
	return strings.Contains(err.Error(), "duplicate key") ||
		strings.Contains(err.Error(), "23505")
}

func (s *UserStorage) GetUserData(ctx context.Context, userID string) (*models.UserData, error) {
	var user models.User
	err := s.db.WithContext(ctx).
		Select("full_name", "username").
		Where("id = ?", userID).
		First(&user).
		Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, status.Error(codes.NotFound, "user not found")
		}
		return nil, status.Error(codes.Internal, "failed to get user data")
	}

	profilePic, err := s.getCurrentProfilePicURL(ctx, userID)
	var currentPic string
	if err != nil {
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, err
		}
		currentPic = ""
	} else {
		currentPic = profilePic
	}

	return &models.UserData{
		UserFullName:          user.FullName,
		UserUsername:          user.Username,
		UserCurrentProfilePic: currentPic,
	}, nil
}

func (s *UserStorage) CreateRefreshToken(ctx context.Context, token *models.RefreshToken) error {
	if token == nil {
		return errors.New("token cannot be nil")
	}

	return s.db.WithContext(ctx).Create(token).Error
}

func (s *UserStorage) UpdateRefreshToken(ctx context.Context, token *models.RefreshToken) error {
	if token == nil {
		return errors.New("token cannot be nil")
	}

	return s.db.WithContext(ctx).
		Model(&models.RefreshToken{}).
		Where("id = ?", token.ID).
		Updates(token).Error
}

func (s *UserStorage) DeleteRefreshToken(ctx context.Context, token *models.RefreshToken) error {
	if token == nil {
		return errors.New("token cannot be nil")
	}

	return s.db.WithContext(ctx).
		Where("id = ?", token.ID).
		Delete(&models.RefreshToken{}).Error
}

func (s *UserStorage) GetRefreshToken(ctx context.Context, tokenID string) (*models.RefreshToken, error) {
	var token models.RefreshToken
	err := s.db.WithContext(ctx).
		Where("id = ?", tokenID).
		First(&token).
		Error

	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, errors.New("refresh token not found")
		}
		return nil, err
	}

	return &token, nil
}

func (s *UserStorage) GetFollowers(ctx context.Context, userID string, page, limit int32) ([]*models.User, int32, error) {
	offset := (page - 1) * limit

	var totalCount int64
	var followerIDs []string
	var followers []*models.User

	err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Exec("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ").Error; err != nil {
			return err
		}

		if err := tx.Model(&models.Followings{}).
			Where("following = ?", userID).
			Count(&totalCount).Error; err != nil {
			return err
		}

		if err := tx.Model(&models.Followings{}).
			Select("follower").
			Where("following = ?", userID).
			Offset(int(offset)).
			Limit(int(limit)).
			Order("created_at DESC").
			Pluck("follower", &followerIDs).Error; err != nil {
			return err
		}

		return nil
	}, &sql.TxOptions{
		Isolation: sql.LevelRepeatableRead,
	})

	if err != nil {
		return nil, 0, err
	}

	return followers, int32(totalCount), nil
}
