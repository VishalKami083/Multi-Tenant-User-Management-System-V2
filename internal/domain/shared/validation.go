package shared

import (
	"net/mail"
	"strings"
)

func ValidEmail(value string) bool {
	if len(value) > 254 {
		return false
	}
	address, err := mail.ParseAddress(value)
	return err == nil && address.Address == value && strings.Contains(value, "@")
}

func ValidCode(value string) bool {
	for i, r := range value {
		if (r < 'a' || r > 'z') && (r < '0' || r > '9') && !(r == '-' && i > 0) {
			return false
		}
	}
	return len(value) >= 2 && value[0] != '-'
}

func ValidPermission(value string) bool {
	parts := strings.Split(value, ":")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return false
	}
	for _, part := range parts {
		for _, r := range part {
			if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '_' && r != '-' {
				return false
			}
		}
	}
	return true
}
