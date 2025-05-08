package config

import (
	"log"

	"github.com/caarlos0/env/v10"
)

type (
	Config struct {
		PsqlCfg  *PsqlConfig  `envPrefix:"PSQL_"`
		MinIoCfg *MinIoConfig `envPrefix:"MINIO_"`
		RedisCfg *RedisConfig `envPrefix:"REDIS_"`
		KafkaCfg *KafkaConfig `envPrefix:"KAFKA_"`
	}

	PsqlConfig struct {
		Host     string `env:"HOST,required"`
		Port     int    `env:"PORT" envDefault:"5432"`
		User     string `env:"USER,required"`
		Password string `env:"PASSWORD,required"`
		DBName   string `env:"DBNAME,required"`
		SSLMode  string `env:"SSLMODE" envDefault:"disable"`
	}

	MinIoConfig struct {
		Endpoint        string `env:"ENDPOINT,required"`
		AccessKeyID     string `env:"ACCESS_KEY_ID,required"`
		SecretAccessKey string `env:"SECRET_ACCESS_KEY,required"`
		Bucket          string `env:"BUCKET,required"`
		UseSSL          bool   `env:"USE_SSL" envDefault:"false"`
		URLExpiry       int64  `env:"URL_EXPIRY" envDefault:"3600"`
	}

	RedisConfig struct {
		Addr     string `env:"ADDR,required"`
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
	cfg := &Config{
		PsqlCfg:  &PsqlConfig{},
		MinIoCfg: &MinIoConfig{},
		RedisCfg: &RedisConfig{},
		KafkaCfg: &KafkaConfig{},
	}

	if err := env.Parse(cfg.PsqlCfg); err != nil {
		log.Fatalf("error parsing PSQL config: %v", err)
	}
	if err := env.Parse(cfg.MinIoCfg); err != nil {
		log.Fatalf("error parsing MinIO config: %v", err)
	}
	if err := env.Parse(cfg.RedisCfg); err != nil {
		log.Fatalf("error parsing Redis config: %v", err)
	}
	if err := env.Parse(cfg.KafkaCfg); err != nil {
		log.Fatalf("error parsing Kafka config: %v", err)
	}

	return cfg
}
