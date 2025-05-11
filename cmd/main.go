package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/confluentinc/confluent-kafka-go/v2/kafka"
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
			newKafkaConsumer,
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

// Create a new gRPC server and register the service
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
			log.Println("Starting user service...")

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

			log.Println("User service started")
			return nil
		},
		OnStop: func(context.Context) error {
			log.Println("Stopping user service...")

			grpcServer.GracefulStop()
			sqlDB, err := db.DB()
			if err != nil {
				log.Printf("Error getting raw db connection: %v", err)
				return err
			}
			if err := sqlDB.Close(); err != nil {
				log.Printf("Error closing database connection: %v", err)
			}

			log.Println("User service stopped")
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
	return logger.NewLogger("/app/user_service.log")
}

func newKafkaConsumer(cfg *config.Config) (*kafka.Consumer, error) {
	config := &kafka.ConfigMap{
		"bootstrap.servers":       "kafka:9092",
		"group.id":                "notification-service-group",
		"auto.offset.reset":       "latest",
		"enable.auto.commit":      true,
		"session.timeout.ms":      6000,
		"heartbeat.interval.ms":   2000,
		"max.poll.interval.ms":    300000,
		"socket.keepalive.enable": true,
	} // TODO: get kafka config values from cfg

	consumer, err := kafka.NewConsumer(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create Kafka consumer: %s", err.Error())
	}

	err = consumer.SubscribeTopics([]string{"user.notifications"}, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to subscribe to topics: %s", err.Error())
	}

	return consumer, nil
}
