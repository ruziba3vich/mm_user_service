package repos

import (
	"context"

	"github.com/ruziba3vich/mm_user_service/genprotos/genprotos/user_protos"
)

type (
	UserRepo interface {
		CreateUser(ctx context.Context, in *user_protos.SignUpRequest) (*user_protos.SignUpResponse, error)
		Login(ctx context.Context, in *user_protos.LoginRequest) (*user_protos.LoginResponse, error)
		Logout(ctx context.Context, in *user_protos.LogoutRequest) (*user_protos.LogoutResponse, error)
		AddProfilePicture(ctx context.Context, in *user_protos.AddProfilePictureRequest) (*user_protos.AddProfilePictureResponse, error)
		RemoveProfilePicture(ctx context.Context, in *user_protos.RemoveProfilePictureRequest) (*user_protos.RemoveProfilePictureResponse, error)
		UpdateUser(ctx context.Context, in *user_protos.UpdateUserRequest) (*user_protos.UpdateUserResponse, error)
	}
)
