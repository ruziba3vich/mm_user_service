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
		RefreshToken(context.Context, *user_protos.RefreshTokenRequest) (*user_protos.RefreshTokenResponse, error)
		AddProfilePicture(ctx context.Context, userId string, fileName string, pictureId string) error
		RemoveProfilePicture(context.Context, *user_protos.RemoveProfilePictureRequest) (*user_protos.RemoveProfilePictureResponse, error)
		UpdateUser(context.Context, *user_protos.UpdateUserRequest) (*user_protos.UpdateUserResponse, error)
		GetUserById(context.Context, *user_protos.GetUserByIdRequest) (*user_protos.GetUserByIdResponse, error)
	}
)
