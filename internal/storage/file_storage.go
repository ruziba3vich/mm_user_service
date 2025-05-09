package storage

import (
	"bytes"
	"context"
	"path/filepath"
	"time"

	"github.com/google/uuid"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	"github.com/ruziba3vich/mm_user_service/pkg/config"
)

type MinioStorage struct {
	client     *minio.Client
	bucketName string
	urlExpiry  int64
}

func NewMinIOStorage(cfg *config.Config) (*MinioStorage, error) {
	client, err := minio.New(cfg.MinIoCfg.Endpoint, &minio.Options{
		Creds:  credentials.NewStaticV4(cfg.MinIoCfg.AccessKeyID, cfg.MinIoCfg.SecretAccessKey, ""),
		Secure: false,
	})
	if err != nil {
		return nil, err
	}
	exists, err := client.BucketExists(context.Background(), cfg.MinIoCfg.Bucket)
	if err != nil {
		return nil, err
	}
	if !exists {
		err = client.MakeBucket(context.Background(), cfg.MinIoCfg.Bucket, minio.MakeBucketOptions{})
		if err != nil {
			return nil, err
		}
	}
	return &MinioStorage{
		client:     client,
		bucketName: cfg.MinIoCfg.Bucket,
		urlExpiry:  int64(cfg.MinIoCfg.URLExpiry),
	}, nil
}

func (s *MinioStorage) CreateFile(ctx context.Context, fileName string, fileContent []byte) (string, string, error) {
	ext := filepath.Ext(fileName)
	generatedName := uuid.New().String() + ext
	_, err := s.client.PutObject(ctx, s.bucketName, generatedName, bytes.NewReader(fileContent), int64(len(fileContent)), minio.PutObjectOptions{})
	if err != nil {
		return "", "", err
	}
	url, err := s.GetFileURL(ctx, generatedName)
	if err != nil {
		return "", "", err
	}
	return generatedName, url, nil
}

func (s *MinioStorage) DeleteFile(ctx context.Context, fileName string) error {
	return s.client.RemoveObject(ctx, s.bucketName, fileName, minio.RemoveObjectOptions{})
}

func (s *MinioStorage) GetFileURL(ctx context.Context, fileName string) (string, error) {
	url, err := s.client.PresignedGetObject(ctx, s.bucketName, fileName, time.Duration(s.urlExpiry)*time.Second, nil)
	if err != nil {
		return "", err
	}
	return url.String(), nil
}
