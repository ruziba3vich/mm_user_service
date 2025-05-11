package service

import (
	"crypto/md5"
	"encoding/binary"
	"fmt"
	"sync"

	"github.com/confluentinc/confluent-kafka-go/v2/kafka"
	"github.com/ruziba3vich/mm_user_service/genprotos/genprotos/user_protos"
	"github.com/ruziba3vich/mm_user_service/pkg/config"
	lgger "github.com/ruziba3vich/prodonik_lgger"
	"google.golang.org/protobuf/proto"
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
	notificationService := &UserNotificationService{
		config:      cfg,
		logger:      logger,
		consumer:    concumer,
		topic:       "user.notifications",
		activeUsers: make(map[string]chan *user_protos.Notification),
		partitions:  partitions,
		mu:          &sync.RWMutex{},
		done:        make(chan struct{}),
	}
	go notificationService.consumeMessages()
	return notificationService
}

func (s *UserNotificationService) Close() error {

	s.logger.Info("closing notification service")
	close(s.done)
	s.mu.Lock()
	for userId, ch := range s.activeUsers {
		close(ch)
		delete(s.activeUsers, userId)
	}

	s.mu.Unlock()
	err := s.consumer.Close()

	if err != nil {
		s.logger.Error("error closing kafka consumer", map[string]any{"error": err.Error()})
		return err
	}

	s.logger.Info("notification service closed")

	return nil
}

func (s *UserNotificationService) registerUser(userId string) chan *user_protos.Notification {
	s.mu.Lock()
	defer s.mu.Unlock()
	if ch, exists := s.activeUsers[userId]; exists {
		s.logger.Debug("user already registered", map[string]any{"user_id": userId})
		return ch
	}

	notifChan := make(chan *user_protos.Notification, 100)
	s.activeUsers[userId] = notifChan
	s.logger.Info("user registered for notifications", map[string]any{"user_id": userId})
	s.updatePartitionAssignments()

	return notifChan
}

func (s *UserNotificationService) unregisterUser(userId string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if ch, exists := s.activeUsers[userId]; exists {
		close(ch)
		delete(s.activeUsers, userId)
		s.logger.Info("user unregistered from notifications", map[string]any{"user_id": userId})
	} else {
		s.logger.Debug("unregisterUser: user not found", map[string]any{"user_id": userId})
		return
	}
	s.updatePartitionAssignments()

}

func (s *UserNotificationService) updatePartitionAssignments() {
	if len(s.activeUsers) == 0 {
		s.logger.Info("no active users, unassigning all partitions")
		if err := s.consumer.Unassign(); err != nil {
			s.logger.Error("failed to unassign partitions", map[string]any{"error": err.Error()})
		}
		return
	}
	neededPartitionsSet := make(map[int32]bool)

	for userId := range s.activeUsers {
		partition := s.getUserPartition(userId)
		neededPartitionsSet[partition] = true
	}

	var partitionsToAssign []kafka.TopicPartition

	for partition := range neededPartitionsSet {
		partitionsToAssign = append(partitionsToAssign, kafka.TopicPartition{
			Topic:     &s.topic,
			Partition: partition,
			Offset:    kafka.OffsetStored,
		})

	}

	if len(partitionsToAssign) > 0 {
		s.logger.Info("assigning partitions", map[string]any{"count": len(partitionsToAssign), "partitions": partitionsToAssign})
		err := s.consumer.Assign(partitionsToAssign)

		if err != nil {
			s.logger.Error("failed to assign partitions", map[string]any{
				"error":      err.Error(),
				"partitions": partitionsToAssign,
			})
		} else {
			s.logger.Info("successfully updated partition assignments", map[string]any{
				"assigned_count": len(partitionsToAssign),
			})
		}
	} else {
		s.logger.Info("no partitions to assign, unassigning all partitions")
		if err := s.consumer.Unassign(); err != nil {
			s.logger.Error("failed to unassign partitions during update (no specific partitions to assign)", map[string]any{"error": err.Error()})
		}
	}
}

func (s *UserNotificationService) getUserPartition(userId string) int32 {
	hash := md5.Sum([]byte(userId))
	hashValue := binary.BigEndian.Uint32(hash[:4])
	return int32(hashValue % uint32(s.partitions))
}

func (s *UserNotificationService) trySendNotification(ch chan<- *user_protos.Notification, n *user_protos.Notification, userId string) {
	defer func() {
		if r := recover(); r != nil {
			s.logger.Warn("recovered panic sending to user channel (likely closed)", map[string]any{
				"user_id": userId,
				"panic":   r,
			})
		}
	}()

	select {
	case ch <- n:
		s.logger.Debug("notification sent to user channel", map[string]any{"user_id": userId})
	default:
		s.logger.Warn("notification buffer full for user, message dropped", map[string]any{
			"user_id": userId,
		})
	}

}

func (s *UserNotificationService) consumeMessages() {
	defer s.logger.Info("consumeMessages goroutine finished")

	s.logger.Info("starting consumeMessages goroutine")

	for {
		select {
		case <-s.done:
			s.logger.Info("consumeMessages: shutdown signal received, exiting loop")
			return

		default:
			ev := s.consumer.Poll(100)
			if ev == nil {
				continue
			}

			switch e := ev.(type) {
			case *kafka.Message:
				if e.Key == nil {
					s.logger.Warn("received kafka message with nil key", map[string]any{
						"topic":     *e.TopicPartition.Topic,
						"partition": e.TopicPartition.Partition,
						"offset":    e.TopicPartition.Offset,
					})
					continue
				}

				userId := string(e.Key)

				var notification user_protos.Notification
				if err := proto.Unmarshal(e.Value, &notification); err != nil {
					s.logger.Error("failed to unmarshal notification", map[string]any{
						"error":   err.Error(),
						"user_id": userId,
						"offset":  e.TopicPartition.Offset,
					})
					continue
				}

				if notification.ReceiverId != userId {
					s.logger.Warn("notification key mismatch with message payload", map[string]any{
						"kafka_key":          userId,
						"payload_receiverId": notification.ReceiverId,
						"notification_type":  notification.Type,
					})
				}

				s.mu.RLock()
				ch, exists := s.activeUsers[userId]
				s.mu.RUnlock()

				if !exists {
					s.logger.Debug("no active stream for user, notification dropped or will be picked up later if user connects", map[string]any{
						"user_id": userId,
					})
					continue
				}

				s.trySendNotification(ch, &notification, userId)

			case kafka.Error:
				s.logger.Error("Kafka error in consumer poll", map[string]any{
					"code":  e.Code(),
					"error": e.Error(),
				})

				if e.IsFatal() {
					s.logger.Error("Fatal Kafka error encountered, attempting to close service.", map[string]any{"error": e.Error()})
					close(s.done)
					return
				}

			case kafka.AssignedPartitions:
				s.logger.Info("Kafka partitions assigned", map[string]any{"partitions": e.Partitions})

			case kafka.RevokedPartitions:
				s.logger.Info("Kafka partitions revoked", map[string]any{"partitions": e.Partitions})

			default:
				s.logger.Debug("kafka consumer poll: unhandled event type", map[string]any{"event_type": fmt.Sprintf("%T", e)})
			}
		}
	}
}
