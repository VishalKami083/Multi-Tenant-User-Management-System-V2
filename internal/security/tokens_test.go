package security

import (
	"testing"
	"time"
)

func TestAccessTokenIsTenantScopedAndExpires(t *testing.T) {
	manager := NewTokenManager("test-secret-that-is-long-enough-for-hmac", time.Minute, time.Hour)
	now := time.Now().UTC()
	pair, _, err := manager.Issue("tenant-a", "user-1", now)
	if err != nil {
		t.Fatal(err)
	}
	claims, err := manager.Parse(pair.AccessToken)
	if err != nil {
		t.Fatalf("parse valid access token: %v", err)
	}
	if claims.TenantID != "tenant-a" || claims.UserID != "user-1" {
		t.Fatalf("unexpected identity claims: tenant=%q user=%q", claims.TenantID, claims.UserID)
	}
	expired, _, err := manager.Issue("tenant-a", "user-1", now.Add(-2*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Parse(expired.AccessToken); err == nil {
		t.Fatal("expected expired token to be rejected")
	}
	if pair.RefreshToken == "" || pair.RefreshToken == pair.AccessToken {
		t.Fatal("refresh credential should be a distinct opaque token")
	}
}
