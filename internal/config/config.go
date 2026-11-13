package config

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"time"
)

type Config struct {
	Address            string
	DatabaseURL        string
	JWTSecret          string
	AccessTokenTTL     time.Duration
	RefreshTokenTTL    time.Duration
	PermissionCacheTTL time.Duration
	DBMaxConns         int32
}

func Load() (Config, error) {
	cfg := Config{
		Address:     env("APP_ADDR", ":8080"),
		DatabaseURL: os.Getenv("DATABASE_URL"),
		JWTSecret:   os.Getenv("JWT_SECRET"),
		DBMaxConns:  30,
	}
	if cfg.DatabaseURL == "" {
		return Config{}, errors.New("DATABASE_URL is required")
	}
	if len(cfg.JWTSecret) < 32 {
		return Config{}, errors.New("JWT_SECRET must be at least 32 characters")
	}
	var err error
	if cfg.AccessTokenTTL, err = duration("ACCESS_TOKEN_TTL", "15m"); err != nil {
		return Config{}, err
	}
	if cfg.RefreshTokenTTL, err = duration("REFRESH_TOKEN_TTL", "720h"); err != nil {
		return Config{}, err
	}
	if cfg.PermissionCacheTTL, err = duration("PERMISSION_CACHE_TTL", "30s"); err != nil {
		return Config{}, err
	}
	if raw := os.Getenv("DB_MAX_CONNS"); raw != "" {
		n, parseErr := strconv.ParseInt(raw, 10, 32)
		if parseErr != nil || n < 1 {
			return Config{}, fmt.Errorf("DB_MAX_CONNS must be a positive integer")
		}
		cfg.DBMaxConns = int32(n)
	}
	return cfg, nil
}

func duration(key, fallback string) (time.Duration, error) {
	raw := env(key, fallback)
	d, err := time.ParseDuration(raw)
	if err != nil || d <= 0 {
		return 0, fmt.Errorf("%s must be a positive duration", key)
	}
	return d, nil
}

func env(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}
