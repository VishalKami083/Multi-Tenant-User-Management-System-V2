package service

import "testing"

func TestValidationHelpers(t *testing.T) {
	tests := []struct {
		name string
		got  bool
		want bool
	}{
		{"tenant code", validCode("acme-west"), true},
		{"tenant code leading hyphen", validCode("-acme"), false},
		{"tenant code uppercase", validCode("Acme"), false},
		{"email", validEmail("owner@example.com"), true},
		{"email malformed", validEmail("not-an-email"), false},
		{"permission", validPermission("user:create"), true},
		{"permission missing action", validPermission("user:"), false},
		{"permission extra delimiter", validPermission("user:create:all"), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.want {
				t.Fatalf("got %v, want %v", tt.got, tt.want)
			}
		})
	}
}
