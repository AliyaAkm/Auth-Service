package config

import (
	"fmt"
	"github.com/caarlos0/env/v11"
	"net"
	"os"
	"strings"
	"time"
)

type DbConfig struct {
	URL      string `env:"URL" envDefault:""`
	Host     string `env:"HOST" envDefault:""`
	Port     int    `env:"PORT" envDefault:"0"`
	User     string `env:"USER" envDefault:""`
	Password string `env:"PASSWORD" envDefault:""`
	DBName   string `env:"NAME" envDefault:""`
	SSLMode  string `env:"SSLMODE" envDefault:"disable"`
}

type JWTConfig struct {
	Secret     string        `env:"SECRET"`
	Issuer     string        `env:"ISSUER"`
	Audience   string        `env:"AUDIENCE"`
	AccessTTL  time.Duration `env:"ACCESS_TTL"`
	RefreshTTL time.Duration `env:"REFRESH_TTL"`
}

type SMTPConfig struct {
	Host                 string `env:"HOST"`
	Port                 int    `env:"PORT"`
	Username             string `env:"USERNAME"`
	Password             string `env:"PASSWORD"`
	FromEmail            string `env:"FROM_EMAIL"`
	FromName             string `env:"FROM_NAME" envDefault:"Zerde Study"`
	PasswordResetSubject string `env:"PASSWORD_RESET_SUBJECT" envDefault:"Password reset code"`
}

type StorageServiceConfig struct {
	URL     string        `env:"URL" envDefault:"http://localhost:8085"`
	Timeout time.Duration `env:"TIMEOUT" envDefault:"30m"`
}

type NotificationServiceConfig struct {
	URL            string        `env:"URL" envDefault:"http://localhost:8087"`
	Timeout        time.Duration `env:"TIMEOUT" envDefault:"5s"`
	InternalAPIKey string        `env:"INTERNAL_API_KEY" envDefault:""`
}

type Config struct {
	HTTPAddr     string                    `env:"HTTP_ADDR"`
	DB           DbConfig                  `envPrefix:"DB_"`
	JWT          JWTConfig                 `envPrefix:"JWT_"`
	SMTP         SMTPConfig                `envPrefix:"SMTP_"`
	Storage      StorageServiceConfig      `envPrefix:"STORAGE_SERVICE_"`
	Notification NotificationServiceConfig `envPrefix:"NOTIFICATION_SERVICE_"`
}

func ReadEnv() (*Config, error) {
	cfg := new(Config)
	opts := env.Options{
		RequiredIfNoDef: true,
	}
	if err := env.ParseWithOptions(cfg, opts); err != nil {
		return nil, err
	}
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

func (c Config) DatabaseURL() string {
	if strings.TrimSpace(c.DB.URL) != "" {
		return strings.TrimSpace(c.DB.URL)
	}

	return fmt.Sprintf("postgres://%s:%s@%s:%d/%s?sslmode=%s",
		c.DB.User, c.DB.Password, c.DB.Host, c.DB.Port, c.DB.DBName, c.DB.SSLMode,
	)
}

func (c Config) ListenAddr() string {
	port := strings.TrimSpace(os.Getenv("PORT"))
	if port == "" {
		return c.HTTPAddr
	}

	return net.JoinHostPort("", port)
}

func (c Config) validate() error {
	if strings.TrimSpace(c.DB.URL) == "" {
		switch {
		case strings.TrimSpace(c.DB.Host) == "":
			return fmt.Errorf("DB_HOST is required when DB_URL is empty")
		case c.DB.Port == 0:
			return fmt.Errorf("DB_PORT is required when DB_URL is empty")
		case strings.TrimSpace(c.DB.User) == "":
			return fmt.Errorf("DB_USER is required when DB_URL is empty")
		case strings.TrimSpace(c.DB.Password) == "":
			return fmt.Errorf("DB_PASSWORD is required when DB_URL is empty")
		case strings.TrimSpace(c.DB.DBName) == "":
			return fmt.Errorf("DB_NAME is required when DB_URL is empty")
		}
	}

	return nil
}
