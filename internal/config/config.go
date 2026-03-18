package config

import (
	"fmt"
	"github.com/caarlos0/env/v11"
	"time"
)

type DbConfig struct {
	Host     string `env:"HOST"`
	Port     int    `env:"PORT"`
	User     string `env:"USER"`
	Password string `env:"PASSWORD"`
	DBName   string `env:"NAME"`
	SSLMode  string `env:"SSLMODE"`
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

type Config struct {
	HTTPAddr string     `env:"HTTP_ADDR"`
	DB       DbConfig   `envPrefix:"DB_"`
	JWT      JWTConfig  `envPrefix:"JWT_"`
	SMTP     SMTPConfig `envPrefix:"SMTP_"`
}

func ReadEnv() (*Config, error) {
	cfg := new(Config)
	opts := env.Options{
		RequiredIfNoDef: true,
	}
	if err := env.ParseWithOptions(cfg, opts); err != nil {
		return nil, err
	}
	return cfg, nil
}

func (c Config) DatabaseURL() string {
	return fmt.Sprintf("postgres://%s:%s@%s:%d/%s?sslmode=%s",
		c.DB.User, c.DB.Password, c.DB.Host, c.DB.Port, c.DB.DBName, c.DB.SSLMode,
	)
}
