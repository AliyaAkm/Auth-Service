package main

import (
	jwtlib "auth-service/internal/service/jwt"
	"context"
	"errors"
	"github.com/google/uuid"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"auth-service/internal/config"
	"auth-service/internal/http/handlers"
	"auth-service/internal/http/router"
	"auth-service/internal/repo/postgres"
	"auth-service/internal/service/security"
	"auth-service/internal/usecase"

	"github.com/joho/godotenv"
)

func main() {
	_ = godotenv.Load(".env")

	cfg, err := config.ReadEnv()
	if err != nil {
		log.Fatal("configuration error:", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	pool, err := postgres.NewPool(ctx, cfg.DatabaseURL())
	if err != nil {
		log.Fatal("error connecting to the database:", err)
	}
	defer pool.Close()

	userRepo := postgres.NewUserRepo(pool)
	refreshRepo := postgres.NewRefreshRepo(pool)

	hasher := security.PasswordHasher{}

	jwtMgr := jwtlib.New(
		[]byte(cfg.JWT.Secret),
		cfg.JWT.Issuer,
		cfg.JWT.Audience,
		cfg.JWT.AccessTTL,
	)

	authUC := usecase.NewAuth(
		userRepo,
		refreshRepo,
		hasher,
		jwtMgr,
		cfg.JWT.RefreshTTL,
		uuid.New,
		time.Now,
	)

	authH := handlers.NewAuthHandler(authUC, jwtMgr)

	engine := router.New(authH)

	srv := &http.Server{
		Addr:              cfg.HTTPAddr,
		Handler:           engine,
		ReadHeaderTimeout: 5 * time.Second,
	}

	go func() {
		log.Println("auth-service started on", cfg.HTTPAddr)
		if err := srv.ListenAndServe(); err != nil && errors.Is(http.ErrServerClosed, err) {
			log.Println("server error:", err)
		}
	}()

	<-ctx.Done()

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Println("shutdown error:", err)
	}

	log.Println("auth-service stopped")
}
