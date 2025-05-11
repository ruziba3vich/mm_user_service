package service

import (
	"sync"

	"github.com/confluentinc/confluent-kafka-go/v2/kafka"
	"github.com/ruziba3vich/mm_user_service/genprotos/genprotos/user_protos"
	"github.com/ruziba3vich/mm_user_service/pkg/config"
	lgger "github.com/ruziba3vich/prodonik_lgger"
)

type UserNotificationService struct {
	config      *config.Config
	logger      *lgger.Logger
	consumer    *kafka.Consumer
	topic       string
	partitions  int32
	activeUsers map[string]chan *user_protos.Notification
	mu          *sync.RWMutex
	done        chan struct{}
}

func NewUserNotificationService(cfg *config.Config, logger *lgger.Logger, concumer *kafka.Consumer, partitions int32) *UserNotificationService {
	return &UserNotificationService{
		config:      cfg,
		logger:      logger,
		consumer:    concumer,
		topic:       "user.notifications",
		activeUsers: make(map[string]chan *user_protos.Notification),
		partitions:  partitions,
		mu:          &sync.RWMutex{},
		done:        make(chan struct{}),
	}
}


