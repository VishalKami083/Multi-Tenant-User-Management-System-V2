package security

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type Claims struct {
	TenantID string `json:"tid"`
	UserID   string `json:"uid"`
	jwt.RegisteredClaims
}

type TokenPair struct {
	AccessToken      string    `json:"access_token"`
	RefreshToken     string    `json:"refresh_token"`
	TokenType        string    `json:"token_type"`
	AccessExpiresAt  time.Time `json:"access_expires_at"`
	RefreshExpiresAt time.Time `json:"refresh_expires_at"`
}

type TokenManager struct {
	secret     []byte
	accessTTL  time.Duration
	refreshTTL time.Duration
}

func NewTokenManager(secret string, accessTTL, refreshTTL time.Duration) *TokenManager {
	return &TokenManager{secret: []byte(secret), accessTTL: accessTTL, refreshTTL: refreshTTL}
}

func (m *TokenManager) Issue(tenantID, userID string, now time.Time) (TokenPair, []byte, error) {
	refreshBytes := make([]byte, 32)
	if _, err := rand.Read(refreshBytes); err != nil {
		return TokenPair{}, nil, err
	}
	refresh := base64.RawURLEncoding.EncodeToString(refreshBytes)
	refreshExpires := now.Add(m.refreshTTL)
	accessExpires := now.Add(m.accessTTL)
	claims := Claims{
		TenantID: tenantID,
		UserID:   userID,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "multitenant-usermgmt",
			Subject:   userID,
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(accessExpires),
			ID:        base64.RawURLEncoding.EncodeToString(refreshBytes[:16]),
		},
	}
	access, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(m.secret)
	if err != nil {
		return TokenPair{}, nil, err
	}
	return TokenPair{
		AccessToken: access, RefreshToken: refresh, TokenType: "Bearer",
		AccessExpiresAt: accessExpires, RefreshExpiresAt: refreshExpires,
	}, HashRefresh(refresh), nil
}

func (m *TokenManager) Parse(access string) (Claims, error) {
	var claims Claims
	token, err := jwt.ParseWithClaims(access, &claims, func(token *jwt.Token) (any, error) {
		if token.Method != jwt.SigningMethodHS256 {
			return nil, errors.New("unexpected signing method")
		}
		return m.secret, nil
	}, jwt.WithIssuer("multitenant-usermgmt"), jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}))
	if err != nil || token == nil || !token.Valid || claims.TenantID == "" || claims.UserID == "" {
		return Claims{}, errors.New("invalid access token")
	}
	return claims, nil
}

func HashRefresh(token string) []byte {
	hash := sha256.Sum256([]byte(token))
	return hash[:]
}
