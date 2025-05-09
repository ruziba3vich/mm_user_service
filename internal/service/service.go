package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"math/rand"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/oklog/ulid/v2"
	"github.com/ruziba3vich/mm_user_service/genprotos/genprotos/user_protos"
	"github.com/ruziba3vich/mm_user_service/internal/models"
	"github.com/ruziba3vich/mm_user_service/internal/storage"
	lgger "github.com/ruziba3vich/prodonik_lgger"
	"golang.org/x/crypto/bcrypt"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type UserService struct {
	storage *storage.UserStorage
	logger  *lgger.Logger
	user_protos.UnimplementedUserServiceServer
}

func NewUserService(storage *storage.UserStorage, logger *lgger.Logger) *UserService {
	return &UserService{
		storage: storage,
		logger:  logger,
	}
}

func (s *UserService) SignUp(ctx context.Context, req *user_protos.SignUpRequest) (*user_protos.SignUpResponse, error) {
	if req.GetFullName() == "" || req.GetUsername() == "" || req.GetPassword() == "" {
		return nil, status.Error(codes.InvalidArgument, "full name, username and password are required")
	}

	hashedPassword, err := hashPassword(req.GetPassword())
	if err != nil {
		return nil, err
	}

	newUser := &models.User{
		FullName:     req.GetFullName(),
		Username:     req.GetUsername(),
		PasswordHash: hashedPassword,
	}

	createdUser, err := s.storage.CreateUser(ctx, newUser)
	if err != nil {
		s.logger.Error("failed to create user", map[string]any{"error": err.Error()})
		return nil, status.Error(codes.Internal, "failed to create user")
	}

	return &user_protos.SignUpResponse{
		User: createdUser.ToProto(),
	}, nil
}

func (s *UserService) Login(ctx context.Context, req *user_protos.LoginRequest) (*user_protos.LoginResponse, error) {
	if req.GetUsername() == "" || req.GetPassword() == "" || req.GetDeviceId() == "" {
		return nil, status.Error(codes.InvalidArgument, "username, password and device_id are required")
	}

	hashedPassword, err := hashPassword(req.GetPassword())
	if err != nil {
		return nil, err
	}

	user, err := s.storage.ValidateUserCredentials(ctx, req.GetUsername(), hashedPassword)
	if err != nil {
		s.logger.Warn("invalid login attempt", map[string]any{"username": req.GetUsername()})
		return nil, status.Error(codes.Unauthenticated, "invalid credentials")
	}

	accessToken, refreshToken, err := generateTokens(
		user.ID,
		"static-secret",
		time.Duration(1)*time.Hour,
		time.Duration(45*24)*time.Hour,
	)
	if err != nil {
		s.logger.Error("failed to generate tokens", map[string]any{"error": err.Error()})
		return nil, status.Error(codes.Internal, "failed to generate tokens")
	}

	err = s.storage.CreateRefreshToken(ctx, &models.RefreshToken{
		ID:        refreshToken.ID,
		UserID:    user.ID,
		TokenHash: hashToken(refreshToken.Token),
		DeviceID:  req.GetDeviceId(),
		ExpiresAt: refreshToken.ExpiresAt,
	})
	if err != nil {
		s.logger.Error("failed to store refresh token", map[string]any{"error": err.Error()})
		return nil, status.Error(codes.Internal, "failed to store refresh token")
	}

	return &user_protos.LoginResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken.Token,
	}, nil
}

func (s *UserService) Logout(ctx context.Context, req *user_protos.LogoutRequest) (*user_protos.LogoutResponse, error) {
	if req.GetRefreshToken() == "" {
		return nil, status.Error(codes.InvalidArgument, "refresh token is required")
	}

	claims, err := verifyToken(req.GetRefreshToken(), "static-secret")
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, "invalid token")
	}
	err = s.storage.DeleteRefreshToken(ctx, &models.RefreshToken{ID: claims.TokenID})
	if err != nil {
		s.logger.Error("failed to delete refresh token", map[string]any{"error": err.Error()})
		return nil, status.Error(codes.Internal, "failed to logout")
	}

	return &user_protos.LogoutResponse{
		Success: true,
	}, nil
}

func (s *UserService) RefreshToken(ctx context.Context, req *user_protos.RefreshTokenRequest) (*user_protos.RefreshTokenResponse, error) {
	if req.GetRefreshToken() == "" {
		return nil, status.Error(codes.InvalidArgument, "refresh token is required")
	}

	claims, err := verifyToken(req.GetRefreshToken(), "static-secret")
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, "invalid refresh token")
	}

	storedToken, err := s.storage.GetRefreshToken(ctx, claims.TokenID)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, "invalid refresh token")
	}

	if time.Now().After(storedToken.ExpiresAt) {
		return nil, status.Error(codes.Unauthenticated, "refresh token expired")
	}

	newAccessToken, newRefreshToken, err := generateTokens(
		storedToken.UserID,
		"static-secret",
		time.Duration(1)*time.Hour,
		time.Duration(45*24)*time.Hour)
	if err != nil {
		s.logger.Error("failed to generate tokens", map[string]any{"error": err.Error()})
		return nil, status.Error(codes.Internal, "failed to generate tokens")
	}

	err = s.storage.UpdateRefreshToken(ctx, &models.RefreshToken{
		ID:         storedToken.ID,
		TokenHash:  hashToken(newRefreshToken.Token),
		ExpiresAt:  newRefreshToken.ExpiresAt,
		LastUsedAt: time.Now(),
	})
	if err != nil {
		s.logger.Error("failed to update refresh token", map[string]any{"error": err.Error()})
		return nil, status.Error(codes.Internal, "failed to update refresh token")
	}

	return &user_protos.RefreshTokenResponse{
		AccessToken:  newAccessToken,
		RefreshToken: newRefreshToken.Token,
	}, nil
}

func (s *UserService) GetUserById(ctx context.Context, req *user_protos.GetUserByIdRequest) (*user_protos.GetUserByIdResponse, error) {
	if req.GetUserId() == "" {
		return nil, status.Error(codes.InvalidArgument, "user ID is required")
	}

	user, err := s.storage.GetUserById(ctx, req.GetUserId())
	if err != nil {
		s.logger.Error("failed to get user", map[string]any{"error": err.Error()})
		return nil, err
	}

	return &user_protos.GetUserByIdResponse{
		User: &user_protos.User{
			Id:       user.ID,
			Username: user.Username,
			FullName: user.FullName,
			// TODO: add profile pic url, too
		},
	}, nil
}

func (s *UserService) GetUserData(ctx context.Context, req *user_protos.GetUserDataRequest) (*user_protos.GetUserDataResponse, error) {
	if req.GetUserId() == "" {
		return nil, status.Error(codes.InvalidArgument, "user ID is required")
	}

	userData, err := s.storage.GetUserData(ctx, req.GetUserId())
	if err != nil {
		s.logger.Error("failed to get user data", map[string]any{"error": err.Error()})
		return nil, err
	}

	return &user_protos.GetUserDataResponse{
		FullName:      userData.UserFullName,
		Username:      userData.UserUsername,
		ProfilePicUrl: userData.UserCurrentProfilePic,
	}, nil
}

func (s *UserService) AddProfilePicture(ctx context.Context, req *user_protos.AddProfilePictureRequest) (*user_protos.AddProfilePictureResponse, error) {
	// if req.GetUserId() == "" || req.GetFileName() == "" {
	// 	return nil, status.Error(codes.InvalidArgument, "user ID and file name are required")
	// }

	// // Generate picture ID if not provided
	// pictureID := req.GetPicture()
	// if pictureID == "" {
	// 	pictureID = generateUUID()
	// }

	// err := s.storage.AddProfilePicture(ctx, req.GetUserId(), req.GetFileName(), pictureID)
	// if err != nil {
	// 	s.logger.Error("failed to add profile picture", map[string]any{
	// 		"error":  err.Error(),
	// 		"userId": req.GetUserId(),
	// 	})
	// 	return nil, status.Error(codes.Internal, "failed to add profile picture")
	// }

	return &user_protos.AddProfilePictureResponse{
		Message: "",
	}, nil
}

func (s *UserService) RemoveProfilePicture(ctx context.Context, req *user_protos.RemoveProfilePictureRequest) (*user_protos.RemoveProfilePictureResponse, error) {
	// if req.GetUserId() == "" || req.GetFileName() == "" {
	// 	return nil, status.Error(codes.InvalidArgument, "user ID and file name are required")
	// }

	// err := s.storage.RemoveProfilePicture(ctx, req.GetUserId(), req.GetFileName())
	// if err != nil {
	// 	if errors.Is(err, storage.ErrNotFound) {
	// 		return nil, status.Error(codes.NotFound, "profile picture not found")
	// 	}
	// 	s.logger.Error("failed to remove profile picture", map[string]any{
	// 		"error":  err.Error(),
	// 		"userId": req.GetUserId(),
	// 	})
	// 	return nil, status.Error(codes.Internal, "failed to remove profile picture")
	// }

	return &user_protos.RemoveProfilePictureResponse{
		Message: "",
	}, nil
}

func (s *UserService) FollowUser(ctx context.Context, req *user_protos.FollowUserRequest) (*user_protos.FollowUserResponse, error) {
	if req.GetFollowerId() == "" || req.GetFollowToId() == "" {
		return nil, status.Error(codes.InvalidArgument, "follower and following IDs are required")
	}

	if req.GetFollowerId() == req.GetFollowToId() {
		return nil, status.Error(codes.InvalidArgument, "user cannot follow themselves")
	}

	followID := generateUUID()
	if following, err := s.storage.CheckUserAFollowsUserB(ctx, req.GetFollowerId(), req.GetFollowToId()); err != nil {
		return nil, status.Error(codes.Internal, "internal server error: "+err.Error())
	} else if following {
		return nil, err
	}
	err := s.storage.FollowUserBByUserA(ctx, req.GetFollowerId(), req.GetFollowToId(), followID)
	if err != nil {
		// if errors.Is(err, storage.ErrNotFound) {
		// 	return nil, status.Error(codes.NotFound, "user not found")
		// }
		s.logger.Error("failed to follow user", map[string]any{
			"error":     err.Error(),
			"follower":  req.GetFollowerId(),
			"following": req.GetFollowToId(),
		})
		return nil, err
	}

	return &user_protos.FollowUserResponse{
		Success: true,
	}, nil
}

func (s *UserService) Unfollow(ctx context.Context, req *user_protos.UnfollowRequest) (*user_protos.UnfollowResponse, error) {
	if req.GetUnfollowFromId() == "" || req.GetUnfollowerId() == "" {
		return nil, status.Error(codes.InvalidArgument, "follower and following IDs are required")
	}

	if following, err := s.storage.CheckUserAFollowsUserB(ctx, req.GetUnfollowerId(), req.GetUnfollowFromId()); err != nil {
		return nil, status.Error(codes.Internal, "internal server error: "+err.Error())
	} else if !following {
		return nil, status.Error(codes.AlreadyExists, "user does not follow")
	}
	// err := s.storage.FollowUserBByUserA(ctx, req.GetFollowerId(), req.GetFollowToId(), followID)
	// if err != nil {
	// 	// if errors.Is(err, storage.ErrNotFound) {
	// 	// 	return nil, status.Error(codes.NotFound, "user not found")
	// 	// }
	// 	s.logger.Error("failed to follow user", map[string]any{
	// 		"error":     err.Error(),
	// 		"follower":  req.GetUnfollowerId(),
	// 		"following": req.GetUnfollowFromId(),
	// 	})
	// 	return nil, status.Error(codes.Internal, "failed to unfollow user")
	// }

	return &user_protos.UnfollowResponse{
		Success: true,
	}, nil
}

func (s *UserService) GetFollowers(ctx context.Context, req *user_protos.GetFollowersRequest) (*user_protos.GetFollowersResponse, error) {
	if req.GetUserId() == "" {
		return nil, status.Error(codes.InvalidArgument, "user ID is required")
	}

	// followers, err := s.storage.get
	return nil, status.Error(codes.Unimplemented, "get followers not implemented")
}

type TokenWithMetadata struct {
	Token     string
	ID        string
	ExpiresAt time.Time
}

type TokenClaims struct {
	jwt.RegisteredClaims
	TokenID string `json:"tid"`
	UserID  string `json:"uid"`
}

func generateTokens(userID string, secret string, accessExpiry time.Duration, refreshExpiry time.Duration) (accessToken string, refreshToken TokenWithMetadata, err error) {

	accessTokenID := generateUUID()
	accessClaims := TokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(accessExpiry)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Subject:   userID,
		},
		TokenID: accessTokenID,
		UserID:  userID,
	}

	accessJWT := jwt.NewWithClaims(jwt.SigningMethodHS256, accessClaims)
	accessToken, err = accessJWT.SignedString([]byte(secret))
	if err != nil {
		return "", TokenWithMetadata{}, err
	}

	// Generate refresh token
	refreshTokenID := generateUUID()
	refreshClaims := TokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(refreshExpiry)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Subject:   userID,
		},
		TokenID: refreshTokenID,
		UserID:  userID,
	}

	refreshJWT := jwt.NewWithClaims(jwt.SigningMethodHS256, refreshClaims)
	refreshTokenStr, err := refreshJWT.SignedString([]byte(secret))
	if err != nil {
		return "", TokenWithMetadata{}, err
	}

	refreshToken = TokenWithMetadata{
		Token:     refreshTokenStr,
		ID:        refreshTokenID,
		ExpiresAt: time.Now().Add(refreshExpiry),
	}

	return accessToken, refreshToken, nil
}

func generateUUID() string {
	t := time.Now()
	entropy := ulid.Monotonic(rand.New(rand.NewSource(t.UnixNano())), 0)
	return ulid.MustNew(ulid.Timestamp(t), entropy).String()
}

func hashToken(token string) string {
	hash := sha256.Sum256([]byte(token))
	return hex.EncodeToString(hash[:])
}

func hashPassword(password string) (string, error) {
	hashedBytes, err := bcrypt.GenerateFromPassword([]byte(password), 12)
	// TODO: take the static value from config
	if err != nil {
		return "", err
	}
	return string(hashedBytes), nil
}

// CheckPassword compares a plaintext password with a hashed password
func checkPassword(hashedPassword, plainPassword string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(plainPassword))
	return err == nil
}

func verifyToken(tokenString, secret string) (*TokenClaims, error) {
	token, err := jwt.ParseWithClaims(
		tokenString,
		&TokenClaims{},
		func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, errors.New("unexpected signing method")
			}
			return []byte(secret), nil
		},
		jwt.WithLeeway(5*time.Second), // TODO: take static values from config
	)

	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, errors.New("token expired")
		}
		return nil, errors.New("invalid token")
	}

	if claims, ok := token.Claims.(*TokenClaims); ok && token.Valid {
		if claims.UserID == "" {
			return nil, errors.New("missing user ID in token")
		}
		return claims, nil
	}

	return nil, errors.New("invalid token claims")
}
