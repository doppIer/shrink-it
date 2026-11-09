// Package config loads runtime configuration from environment variables.
package config

import (
	"os"
	"strconv"
	"time"
)

type Config struct {
	Addr                string
	BaseURL             string
	DatabaseURL         string
	RedisURL            string
	AdminToken          string
	TrustProxy          bool
	CacheTTL            time.Duration
	CreateRateLimit     int
	BlocklistPath       string
	SafeBrowsingKey     string
	AllowPrivateTargets bool
	HealthInterval      time.Duration
	HealthFailThreshold int
	HealthBatchSize     int
}

func Load() Config {
	return Config{
		Addr:                env("ADDR", ":8080"),
		BaseURL:             env("BASE_URL", "http://localhost:8080"),
		DatabaseURL:         env("DATABASE_URL", "postgres://shrinkit:shrinkit@localhost:5432/shrinkit?sslmode=disable"),
		RedisURL:            env("REDIS_URL", "redis://localhost:6379/0"),
		AdminToken:          os.Getenv("ADMIN_TOKEN"),
		TrustProxy:          envBool("TRUST_PROXY", false),
		CacheTTL:            envDuration("CACHE_TTL", 10*time.Minute),
		CreateRateLimit:     envInt("CREATE_RATE_LIMIT", 30),
		BlocklistPath:       os.Getenv("BLOCKLIST_PATH"),
		SafeBrowsingKey:     os.Getenv("SAFE_BROWSING_API_KEY"),
		AllowPrivateTargets: envBool("ALLOW_PRIVATE_TARGETS", false),
		HealthInterval:      envDuration("HEALTH_INTERVAL", 15*time.Minute),
		HealthFailThreshold: envInt("HEALTH_FAIL_THRESHOLD", 3),
		HealthBatchSize:     envInt("HEALTH_BATCH_SIZE", 50),
	}
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func envInt(k string, def int) int {
	if v, err := strconv.Atoi(os.Getenv(k)); err == nil {
		return v
	}
	return def
}

func envBool(k string, def bool) bool {
	if v, err := strconv.ParseBool(os.Getenv(k)); err == nil {
		return v
	}
	return def
}

func envDuration(k string, def time.Duration) time.Duration {
	if v, err := time.ParseDuration(os.Getenv(k)); err == nil {
		return v
	}
	return def
}
