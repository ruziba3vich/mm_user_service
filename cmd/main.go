package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/ruziba3vich/mm_user_service/genprotos/genprotos/user_protos"
	"github.com/ruziba3vich/mm_user_service/internal/service"
	"github.com/ruziba3vich/mm_user_service/internal/storage"
	"github.com/ruziba3vich/mm_user_service/pkg/config"
	logger "github.com/ruziba3vich/prodonik_lgger"
	"go.uber.org/fx"
	"google.golang.org/grpc"
	"gorm.io/gorm"
)

func main() {
	app := fx.New(
		fx.Provide(
			config.LoadConfig,
			newLogger,
			storage.NewGORM,
			storage.NewUserStorage,
			storage.NewMinIOStorage,
			service.NewUserService,
			newGrpcServer,
		),
		fx.Invoke(registerHooks),
	)

	app.Run()
}

// Create a new gRPC server and register the logging service
func newGrpcServer(srv *service.UserService) *grpc.Server {
	server := grpc.NewServer()
	user_protos.RegisterUserServiceServer(server, srv)
	return server
}

// Register application lifecycle hooks
func registerHooks(
	lc fx.Lifecycle,
	db *gorm.DB,
	grpcServer *grpc.Server,
	cfg *config.Config,
) {
	lc.Append(fx.Hook{
		OnStart: func(context.Context) error {
			log.Println("Starting logging service...")

			listener, err := net.Listen("tcp", fmt.Sprintf(":%s", cfg.GRPCPort))
			if err != nil {
				return fmt.Errorf("failed to listen on port %s: %s", cfg.GRPCPort, err.Error())
			}

			log.Printf("gRPC server listening on port %s", cfg.GRPCPort)

			go func() {
				if err := grpcServer.Serve(listener); err != nil {
					log.Fatalf("Failed to serve gRPC: %v", err)
				}
			}()

			log.Println("Logging service started")
			return nil
		},
		OnStop: func(context.Context) error {
			log.Println("Stopping logging service...")

			grpcServer.GracefulStop()
			sqlDB, err := db.DB()
			if err != nil {
				log.Printf("Error getting raw db connection: %v", err)
				return err
			}
			if err := sqlDB.Close(); err != nil {
				log.Printf("Error closing database connection: %v", err)
			}

			log.Println("Logging service stopped")
			return nil
		},
	})

	// Setup signal handling for graceful shutdown
	go func() {
		signals := make(chan os.Signal, 1)
		signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)
		<-signals

		log.Println("Received shutdown signal")
	}()
}

func newLogger() (*logger.Logger, error) {
	return logger.NewLogger("/app/logs/article_service.log")
}
