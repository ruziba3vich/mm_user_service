package storage

import (
	"context"
	"time"

	"github.com/ruziba3vich/mm_user_service/genprotos/genprotos/user_protos"
	"github.com/ruziba3vich/mm_user_service/internal/models"
	"github.com/ruziba3vich/mm_user_service/internal/repos"
	"gorm.io/gorm"
)

// userRepository implements UserRepo
type userRepository struct {
	db *gorm.DB
}

// NewUserRepository creates a new userRepository
func NewUserRepository(db *gorm.DB) repos.UserRepo {
	return &userRepository{db: db}
}

// SignUp stores a new user
func (r *userRepository) SignUp(ctx context.Context, in *user_protos.SignUpRequest) (*user_protos.SignUpResponse, error) {
	user := models.User{
		FullName:     in.FullName,
		Username:     in.Username,
		PasswordHash: in.Password,
	}

	if err := r.db.WithContext(ctx).Create(&user).Error; err != nil {
		return nil, err
	}

	return &user_protos.SignUpResponse{
		User: &user_protos.User{
			Id:        user.ID,
			FullName:  user.FullName,
			Username:  user.Username,
			CreatedAt: user.CreatedAt.Format(time.RFC3339),
		},
	}, nil
}

// Login retrieves a user by username
func (r *userRepository) Login(ctx context.Context, in *user_protos.LoginRequest) (*user_protos.LoginResponse, error) {
	var user models.User
	if err := r.db.WithContext(ctx).Where("username = ?", in.Username).First(&user).Error; err != nil {
		return nil, err
	}

	refreshToken := models.RefreshToken{
		UserID: user.ID,
		// TokenHash: in.RefreshToken, // Assumes service layer hashed token
		DeviceID:  in.DeviceId,
		ExpiresAt: time.Now().Add(30 * 24 * time.Hour),
	}

	if err := r.db.WithContext(ctx).Create(&refreshToken).Error; err != nil {
		return nil, err
	}

	return &user_protos.LoginResponse{
		User: &user_protos.User{
			Id:        user.ID,
			FullName:  user.FullName,
			Username:  user.Username,
			CreatedAt: user.CreatedAt.Format(time.RFC3339),
		},
		// AccessToken:  in.AccessToken, // Assumes service layer generated token
		// RefreshToken: in.RefreshToken,
		DeviceId: in.DeviceId,
	}, nil
}

// Logout deletes a refresh token
func (r *userRepository) Logout(ctx context.Context, in *user_protos.LogoutRequest) (*user_protos.LogoutResponse, error) {
	result := r.db.WithContext(ctx).
		Where("user_id = ? AND token_hash = ? AND device_id = ?", in.UserId, in.RefreshToken, in.DeviceId).
		Delete(&models.RefreshToken{})
	if result.Error != nil {
		return nil, result.Error
	}
	if result.RowsAffected == 0 {
		return nil, gorm.ErrRecordNotFound
	}

	return &user_protos.LogoutResponse{Success: true}, nil
}

// RefreshToken updates a refresh token
func (r *userRepository) RefreshToken(ctx context.Context, in *user_protos.RefreshTokenRequest) (*user_protos.RefreshTokenResponse, error) {
	var refreshToken models.RefreshToken
	if err := r.db.WithContext(ctx).
		Where("user_id = ? AND token_hash = ? AND device_id = ?", in.UserId, in.RefreshToken, in.DeviceId).
		First(&refreshToken).Error; err != nil {
		return nil, err
	}

	updates := map[string]interface{}{
		"token_hash":   in.RefreshToken,
		"expires_at":   time.Now().Add(30 * 24 * time.Hour),
		"last_used_at": time.Now(),
	}
	if err := r.db.WithContext(ctx).
		Where("id = ?", refreshToken.ID).
		Updates(updates).Error; err != nil {
		return nil, err
	}

	return &user_protos.RefreshTokenResponse{
		// AccessToken:  in.AccessToken,
		RefreshToken: in.RefreshToken,
		DeviceId:     in.DeviceId,
	}, nil
}

// AddProfilePicture appends a profile picture URL
func (r *userRepository) AddProfilePicture(ctx context.Context, in *user_protos.AddProfilePictureRequest) (*user_protos.AddProfilePictureResponse, error) {
	fakeUrl := in.FileName
	result := r.db.WithContext(ctx).Model(&models.User{}).
		Where("id = ?", in.UserId).
		Update("profile_pics", gorm.Expr("array_append(profile_pics, ?)", fakeUrl))
	if result.Error != nil {
		return nil, result.Error
	}
	if result.RowsAffected == 0 {
		return nil, gorm.ErrRecordNotFound
	}

	return &user_protos.AddProfilePictureResponse{Message: "Profile picture added"}, nil
}

// RemoveProfilePicture removes a profile picture by index
func (r *userRepository) RemoveProfilePicture(ctx context.Context, in *user_protos.RemoveProfilePictureRequest) (*user_protos.RemoveProfilePictureResponse, error) {
	return nil, nil
}

// UpdateUser updates user fields
func (r *userRepository) UpdateUser(ctx context.Context, in *user_protos.UpdateUserRequest) (*user_protos.UpdateUserResponse, error) {
	updates := map[string]interface{}{
		"full_name": in.FullName,
		"username":  in.Username,
	}
	result := r.db.WithContext(ctx).Model(&models.User{}).Where("id = ?", in.UserId).Updates(updates)
	if result.Error != nil {
		return nil, result.Error
	}
	if result.RowsAffected == 0 {
		return nil, gorm.ErrRecordNotFound
	}

	var user models.User
	if err := r.db.WithContext(ctx).Where("id = ?", in.UserId).First(&user).Error; err != nil {
		return nil, err
	}

	return &user_protos.UpdateUserResponse{
		User: &user_protos.User{
			Id:       user.ID,
			FullName: user.FullName,
			Username: user.Username,
			// ProfilePics: user.ProfilePics,
			CreatedAt: user.CreatedAt.Format(time.RFC3339),
		},
	}, nil
}

// GetUserById retrieves a user by ID
func (r *userRepository) GetUserById(ctx context.Context, in *user_protos.GetUserByIdRequest) (*user_protos.GetUserByIdResponse, error) {
	var user models.User
	if err := r.db.WithContext(ctx).Where("id = ?", in.UserId).First(&user).Error; err != nil {
		return nil, err
	}

	return &user_protos.GetUserByIdResponse{
		UserId:   user.ID,
		FullName: user.FullName,
		Username: user.Username,
		// ProfilePics: user.ProfilePics,
	}, nil
}

//TODO: the storage is not complete, should check the logic
