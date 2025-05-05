package repos

import (
	"context"

	"github.com/ruziba3vich/mm_user_service/genprotos/genprotos/user_protos"
)

type (
	UserRepo interface {
		SignUp(context.Context, *user_protos.SignUpRequest) (*user_protos.SignUpResponse, error)
		Login(context.Context, *user_protos.LoginRequest) (*user_protos.LoginResponse, error)
		Logout(context.Context, *user_protos.LogoutRequest) (*user_protos.LogoutResponse, error)
		RefreshToken(context.Context, *user_protos.RefreshTokenRequest) (*user_protos.RefreshTokenResponse, error)
		AddProfilePicture(context.Context, *user_protos.AddProfilePictureRequest) (*user_protos.AddProfilePictureResponse, error)
		RemoveProfilePicture(context.Context, *user_protos.RemoveProfilePictureRequest) (*user_protos.RemoveProfilePictureResponse, error)
		UpdateUser(context.Context, *user_protos.UpdateUserRequest) (*user_protos.UpdateUserResponse, error)
		GetUserById(context.Context, *user_protos.GetUserByIdRequest) (*user_protos.GetUserByIdResponse, error)
	}
)
