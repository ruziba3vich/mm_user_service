package repos

import (
	"context"

	"github.com/ruziba3vich/mm_user_service/genprotos/genprotos/user_protos"
	"github.com/ruziba3vich/mm_user_service/internal/models"
)

type (
	UserRepo interface {
		CreateUser(ctx context.Context, user *models.User) (*models.User, error)
		ValidateUserCredentials(ctx context.Context, username string, passwordHash string) (*models.User, error)
		Logout(context.Context, *user_protos.LogoutRequest) (*user_protos.LogoutResponse, error)
		AddProfilePicture(ctx context.Context, userId string, fileName string, pictureId string) error
		RemoveProfilePicture(ctx context.Context, userId, fileName string) error
		UpdateUser(ctx context.Context, filter map[string]any) (*models.User, error)
		GetUserById(ctx context.Context, userID string) (*models.User, error)
		GetUserProfilePics(ctx context.Context, userID string) ([]*models.ProfilePicture, error)
		CheckUserAFollowsUserB(ctx context.Context, userA, userB string) error
		FollowUserBByUserA(ctx context.Context, userA, userB string) error
		GetUserData(ctx context.Context, userID string) (*models.UserData, error)
		CreateRefreshToken(ctx context.Context, token *models.RefreshToken) error
		UpdateRefreshToken(ctx context.Context, token *models.RefreshToken) error
		DeleteRefreshToken(ctx context.Context, token *models.RefreshToken) error
		GetRefreshToken(ctx context.Context, tokenID string) (*models.RefreshToken, error)
		UnfollowUserBByUserA(ctx context.Context, userA, userB string) error
	}
)
