package postgres

import (
	"context"
	"github.com/jackc/pgx/v5/pgxpool"
	"time"
)

func NewPool(ctx context.Context, url string) (*pgxpool.Pool, error) {
	cfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		return nil, err
	}
	cfg.MaxConns = 10                      // todo: перенести в енв
	cfg.MaxConnLifetime = 30 * time.Minute // todo: перенести в енв
	return pgxpool.NewWithConfig(ctx, cfg)
}
