package shared

import "testing"

func TestValidationHelpers(t *testing.T) {
	tests := []struct {
		name string
		got  bool
		want bool
	}{
		{"tenant code", ValidCode("acme-west"), true},
		{"tenant code leading hyphen", ValidCode("-acme"), false},
		{"tenant code uppercase", ValidCode("Acme"), false},
		{"email", ValidEmail("owner@example.com"), true},
		{"email malformed", ValidEmail("not-an-email"), false},
		{"permission", ValidPermission("user:create"), true},
		{"permission missing action", ValidPermission("user:"), false},
		{"permission extra delimiter", ValidPermission("user:create:all"), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.want {
				t.Fatalf("got %v, want %v", tt.got, tt.want)
			}
		})
	}
}
