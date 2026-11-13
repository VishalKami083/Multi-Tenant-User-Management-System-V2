package repository

import "time"

type Tenant struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Code   string `json:"code"`
	Status string `json:"status"`
}

type User struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Email     string    `json:"email"`
	CreatedAt time.Time `json:"created_at"`
}

type Role struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
}

type AuditEntry struct {
	ID         int64          `json:"id"`
	ActorID    *string        `json:"actor_id"`
	Action     string         `json:"action"`
	TargetType string         `json:"target_type"`
	TargetID   string         `json:"target_id"`
	Details    map[string]any `json:"details"`
	CreatedAt  time.Time      `json:"created_at"`
}

type LoginRecord struct {
	TenantID         string
	TenantStatus     string
	UserID           string
	UserName         string
	Email            string
	PasswordHash     string
	MembershipStatus string
}

type Permission struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

type RefreshedIdentity struct {
	TenantID string
	UserID   string
}
