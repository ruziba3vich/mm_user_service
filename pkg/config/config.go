package config

import (
	"fmt"
	"log"
	"os"

	"github.com/joho/godotenv"
)

type (
	Config struct {
		PsqlCfg  *PsqlConfig  `envPrefix:"PSQL_"`
		MinIoCfg *MinIoConfig `envPrefix:"MINIO_"`
		RedisCfg *RedisConfig `envPrefix:"REDIS_"`
		KafkaCfg *KafkaConfig `envPrefix:"KAFKA_"`
		GRPCPort string       `envPrefix:"GRPC_"`
	}

	PsqlConfig struct {
		Dsn string `env:"PSQL_DSQN"`
	}

	MinIoConfig struct {
		Endpoint        string `env:"ENDPOINT"`
		AccessKeyID     string `env:"ACCESS_KEY_ID"`
		SecretAccessKey string `env:"SECRET_ACCESS_KEY"`
		Bucket          string `env:"BUCKET" envDefault:"userservice"`
		UseSSL          bool   `env:"USE_SSL" envDefault:"false"`
		URLExpiry       int64  `env:"URL_EXPIRY" envDefault:"3600"`
	}

	RedisConfig struct {
		Host     string
		Port     string
		Addr     string `env:"ADDR"`
		Password string `env:"PASSWORD"`
		DB       int    `env:"DB" envDefault:"0"`
	}

	KafkaConfig struct {
		Brokers []string `env:"BROKERS" envSeparator:"," required:"true"`
		Topic   string   `env:"TOPIC,required"`
		GroupID string   `env:"GROUP_ID" envDefault:"my-group"`
	}
)

func LoadConfig() *Config {
	err := godotenv.Load()
	if err != nil {
		log.Println("No .env file found. Using system environment variables.")
	}

	return &Config{
		MinIoCfg: &MinIoConfig{
			Endpoint:        getEnv("MINIO_ENDPOINT", "localhost:9000"),
			AccessKeyID:     getEnv("MINIO_ACCESS_KEY", "admin"),
			SecretAccessKey: getEnv("MINIO_SECRET_KEY", "secretpass"),
			Bucket:          getEnv("MINIO_BUCKET", "mediumlike"),
			URLExpiry:       int64(getEnvInt("MINIO_URL_EXPIRY", 3_600)),
		},
		RedisCfg: &RedisConfig{
			Host:     getEnv("REDIS_HOST", "localhost"),
			Port:     getEnv("REDIS_PORT", "6379"),
			Password: getEnv("REDIS_PASSWORD", ""),
			DB:       getEnvInt("REDIS_DB", 0),
		},
		PsqlCfg: &PsqlConfig{
			Dsn: getEnv("DB_DSN", "host=postgres user=postgres password=secret dbname=article_service port=5432 sslmode=disable TimeZone=Asia/Tashkent"),
		},
		GRPCPort: getEnv("GRPC_PORT", "7373"),
	}
}

// getEnv retrieves environment variables with a fallback default value
func getEnv(key, fallback string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return fallback
}

// getEnvInt retrieves an integer environment variable
func getEnvInt(key string, fallback int) int {
	if value, exists := os.LookupEnv(key); exists {
		var intValue int
		_, err := fmt.Sscanf(value, "%d", &intValue)
		if err == nil {
			return intValue
		}
	}
	return fallback
}
