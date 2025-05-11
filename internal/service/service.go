package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/ruziba3vich/mm_user_service/genprotos/genprotos/user_protos"
	"github.com/ruziba3vich/mm_user_service/internal/models"
	"github.com/ruziba3vich/mm_user_service/internal/repos"
	"github.com/ruziba3vich/mm_user_service/internal/storage"
	lgger "github.com/ruziba3vich/prodonik_lgger"
	"golang.org/x/crypto/bcrypt"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type UserService struct {
	storage repos.UserRepo
	logger  *lgger.Logger
	user_protos.UnimplementedUserServiceServer
	fileStorage         *storage.MinioStorage
	notificationService *UserNotificationService
}

func NewUserService(
	storage repos.UserRepo,
	fileStorage *storage.MinioStorage,
	logger *lgger.Logger,
	notificationService *UserNotificationService) *UserService {
	return &UserService{
		storage:             storage,
		logger:              logger,
		fileStorage:         fileStorage,
		notificationService: notificationService,
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
		ID:           generateUUID(),
		FullName:     req.GetFullName(),
		Username:     req.GetUsername(),
		PasswordHash: hashedPassword,
		CreatedAt:    time.Now(),
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
	if !checkPassword(user.PasswordHash, req.GetPassword()) {
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
		User:         user.ToProto(),
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

	userData, err := s.storage.GetUserData(ctx, req.GetUserId())
	if err != nil {
		s.logger.Error("failed to get user", map[string]any{"error": err.Error()})
		return nil, err
	}

	return &user_protos.GetUserByIdResponse{
		User: &user_protos.User{
			Id:             user.ID,
			Username:       user.Username,
			FullName:       user.FullName,
			ProfilePicUrl:  userData.UserCurrentProfilePic,
			FollowersCount: int32(user.FollowersCount),
			CreatedAt:      timestamppb.New(user.CreatedAt),
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
	if req.GetUserId() == "" || req.GetFileName() == "" || req.Picture == nil || len(req.Picture) == 0 {
		return nil, status.Error(codes.InvalidArgument, "user ID and file name are required")
	}

	pictureID := generateUUID()
	fileName, _, err := s.fileStorage.CreateFile(ctx, req.FileName, req.Picture)
	if err != nil {
		return nil, err
	}

	err = s.storage.AddProfilePicture(ctx, req.GetUserId(), fileName, pictureID)
	if err != nil {
		s.logger.Error("failed to add profile picture", map[string]any{
			"error":  err.Error(),
			"userId": req.GetUserId(),
		})
		return nil, status.Error(codes.Internal, "failed to add profile picture")
	}

	return &user_protos.AddProfilePictureResponse{
		Message: "created successfully",
	}, nil
}

func (s *UserService) RemoveProfilePicture(ctx context.Context, req *user_protos.RemoveProfilePictureRequest) (*user_protos.RemoveProfilePictureResponse, error) {
	if req.GetUserId() == "" || req.GetFileName() == "" {
		return nil, status.Error(codes.InvalidArgument, "user ID and file name are required")
	}

	err := s.storage.RemoveProfilePicture(ctx, req.GetUserId(), req.GetFileName())
	if err != nil {
		s.logger.Error("failed to remove profile picture", map[string]any{
			"error":  err.Error(),
			"userId": req.GetUserId(),
		})
		return nil, status.Error(codes.Internal, "failed to remove profile picture")
	}
	go s.fileStorage.DeleteFile(ctx, req.FileName)

	return &user_protos.RemoveProfilePictureResponse{
		Message: "success",
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
	err := s.storage.UnfollowUserBByUserA(ctx, req.GetUnfollowerId(), req.GetUnfollowFromId())
	if err != nil {
		s.logger.Error("failed to follow user", map[string]any{
			"error":     err.Error(),
			"follower":  req.GetUnfollowerId(),
			"following": req.GetUnfollowFromId(),
		})
		return nil, status.Error(codes.Internal, "failed to unfollow user")
	}

	return &user_protos.UnfollowResponse{
		Success: true,
	}, nil
}

func (s *UserService) GetFollowers(ctx context.Context, req *user_protos.GetFollowersRequest) (*user_protos.GetFollowersResponse, error) {
	if req.GetUserId() == "" {
		return nil, status.Error(codes.InvalidArgument, "user ID is required")
	}

	page, limit := validatePagination(req.GetPage(), req.GetLimit())

	followers, totalCount, err := s.storage.GetFollowers(ctx, req.UserId, page, limit)
	if err != nil {
		s.logger.Error("failed to get followers",
			map[string]any{"error": err.Error(), "user_id": req.UserId})
		return nil, status.Error(codes.Internal, "failed to get followers")
	}

	response := &user_protos.GetFollowersResponse{
		Pagination: &user_protos.PaginationResponse{
			Users:      make([]*user_protos.User, 0, len(followers)),
			TotalCount: int32(totalCount),
			Page:       page,
			Limit:      limit,
		},
	}

	for _, follower := range followers {
		userData, err := s.storage.GetUserData(ctx, follower.ID)
		if err != nil {
			s.logger.Warn("failed to get follower details",
				map[string]any{"error": err.Error(), "follower_id": follower.ID})
			continue
		}

		response.Pagination.Users = append(response.Pagination.Users, &user_protos.User{
			Id:            follower.ID,
			FullName:      userData.UserFullName,
			Username:      userData.UserUsername,
			ProfilePicUrl: userData.UserCurrentProfilePic,
		})
	}

	return response, nil
}

func validatePagination(page, limit int32) (int32, int32) {
	if page < 1 {
		page = 1
	}
	if limit < 1 || limit > 100 {
		limit = 20
	}
	return page, limit
}

func generateTokens(userID string, secret string, accessExpiry time.Duration, refreshExpiry time.Duration) (accessToken string, refreshToken models.TokenWithMetadata, err error) {

	accessTokenID := generateUUID()
	accessClaims := models.TokenClaims{
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
		return "", models.TokenWithMetadata{}, err
	}

	// Generate refresh token
	refreshTokenID := generateUUID()
	refreshClaims := models.TokenClaims{
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
		return "", models.TokenWithMetadata{}, err
	}

	refreshToken = models.TokenWithMetadata{
		Token:     refreshTokenStr,
		ID:        refreshTokenID,
		ExpiresAt: time.Now().Add(refreshExpiry),
	}

	return accessToken, refreshToken, nil
}

func generateUUID() string {
	now := time.Now()
	timeComponent := fmt.Sprintf("%04d%02d%02d%02d%02d%02d%09d",
		now.Year(), now.Month(), now.Day(),
		now.Hour(), now.Minute(), now.Second(),
		now.Nanosecond())
	if len(timeComponent) > 32 {
		timeComponent = timeComponent[:32]
	}
	for len(timeComponent) < 32 {
		timeComponent += "0"
	}
	return fmt.Sprintf("%s-%s-%s-%s-%s",
		timeComponent[0:8],
		timeComponent[8:12],
		timeComponent[12:16],
		timeComponent[16:20],
		timeComponent[20:32])
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

func verifyToken(tokenString, secret string) (*models.TokenClaims, error) {
	token, err := jwt.ParseWithClaims(
		tokenString,
		&models.TokenClaims{},
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

	if claims, ok := token.Claims.(*models.TokenClaims); ok && token.Valid {
		if claims.UserID == "" {
			return nil, errors.New("missing user ID in token")
		}
		return claims, nil
	}

	return nil, errors.New("invalid token claims")
}

func (s *UserService) StreamNotifications(req *user_protos.NotificationRequest, stream user_protos.UserService_StreamNotificationsServer) error {
	if req.UserId == "" {
		s.logger.Error("user_id is required for StreamNotifications", map[string]any{"method": "StreamNotifications"})
		return status.Error(codes.InvalidArgument, "user_id is required")
	}

	userId := req.UserId
	s.logger.Info("user attempting to connect to notification stream", map[string]any{"user_id": userId})
	notificationsChan := s.notificationService.registerUser(userId)

	defer func() {
		s.notificationService.unregisterUser(userId)
		s.logger.Info("notification stream ended, user unregistered", map[string]any{"user_id": userId})
	}()

	s.logger.Info("user notification stream started", map[string]any{"user_id": userId})

	for {
		select {
		case <-stream.Context().Done():
			s.logger.Info("client disconnected, closing notification stream", map[string]any{
				"user_id": userId,
				"error":   stream.Context().Err(),
			})

			return stream.Context().Err()

		case notification, ok := <-notificationsChan:
			if !ok {
				s.logger.Warn("notificationsChan closed for user, possibly service shutdown", map[string]any{"user_id": userId})
				return status.Error(codes.Unavailable, "notification service unavailable or user channel closed")
			}

			s.logger.Info("sending notification to user via gRPC stream", map[string]any{
				"user_id":           userId,
				"notification_type": notification.Type,
			})

			if err := stream.Send(notification); err != nil {
				s.logger.Error("failed to send notification to gRPC stream", map[string]any{
					"user_id": userId,
					"error":   err.Error(),
				})

				return status.Errorf(codes.Internal, "failed to send notification: %v", err)
			}
		}
	}
}
