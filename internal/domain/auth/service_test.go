package auth

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/vishalKami083/multitenant-usermgmt/internal/domain/shared"
	repoData "github.com/vishalKami083/multitenant-usermgmt/internal/repository/shared"
	"github.com/vishalKami083/multitenant-usermgmt/internal/security"
	"golang.org/x/crypto/bcrypt"
)

type fakeRepository struct {
	loginRecord       repoData.LoginRecord
	findErr           error
	failedLoginErr    error
	loginAuditErr     error
	refreshStoreErr   error
	failedLoginCalls  int
	loginAuditCalls   int
	refreshStoreCalls int
	lastTenantCode    string
	lastLookupCode    string
	lastLookupEmail   string
}

func (r *fakeRepository) FindLogin(_ context.Context, tenantCode, email string) (repoData.LoginRecord, error) {
	r.lastLookupCode = tenantCode
	r.lastLookupEmail = email
	return r.loginRecord, r.findErr
}

func (r *fakeRepository) StoreRefresh(context.Context, []byte, string, string, time.Time) error {
	r.refreshStoreCalls++
	return r.refreshStoreErr
}

func (*fakeRepository) RefreshIdentity(context.Context, []byte, time.Time) (repoData.RefreshedIdentity, error) {
	return repoData.RefreshedIdentity{}, nil
}

func (*fakeRepository) RotateRefresh(context.Context, []byte, []byte, time.Time, time.Time) (repoData.RefreshedIdentity, error) {
	return repoData.RefreshedIdentity{}, nil
}

func (*fakeRepository) RevokeRefresh(context.Context, []byte, time.Time) error { return nil }

func (r *fakeRepository) RecordLogin(context.Context, string, string) error {
	r.loginAuditCalls++
	return r.loginAuditErr
}

func (r *fakeRepository) RecordFailedLogin(_ context.Context, tenantCode string) error {
	r.failedLoginCalls++
	r.lastTenantCode = tenantCode
	return r.failedLoginErr
}

func TestLoginRejectsInactiveTenantOrMembershipAndAuditsFailure(t *testing.T) {
	passwordHash, err := bcrypt.GenerateFromPassword([]byte("correct-password"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name         string
		tenantStatus string
		memberStatus string
		password     string
		findErr      error
	}{
		{name: "suspended tenant", tenantStatus: "suspended", memberStatus: "active", password: "correct-password"},
		{name: "suspended membership", tenantStatus: "active", memberStatus: "suspended", password: "correct-password"},
		{name: "incorrect password", tenantStatus: "active", memberStatus: "active", password: "wrong-password"},
		{name: "unknown tenant user", findErr: repoData.ErrNotFound},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := &fakeRepository{
				loginRecord: repoData.LoginRecord{
					TenantID: "tenant-id", TenantStatus: tt.tenantStatus,
					UserID: "user-id", PasswordHash: string(passwordHash),
					MembershipStatus: tt.memberStatus,
				},
				findErr: tt.findErr,
			}
			service := New(repo, security.NewTokenManager("test-secret-at-least-32-characters", time.Minute, time.Hour))

			_, err := service.Login(context.Background(), " Acme ", "user@example.test", tt.password)
			var serviceErr *shared.Error
			if !errors.As(err, &serviceErr) || serviceErr.Status != 401 {
				t.Fatalf("Login() error = %v, want unauthorized", err)
			}
			if repo.failedLoginCalls != 1 {
				t.Fatalf("failed-login audit calls = %d, want 1", repo.failedLoginCalls)
			}
			if repo.lastTenantCode != "acme" {
				t.Fatalf("audited tenant code = %q, want normalized code %q", repo.lastTenantCode, "acme")
			}
			if repo.lastLookupCode != "acme" || repo.lastLookupEmail != "user@example.test" {
				t.Fatalf("login lookup used code=%q email=%q, want normalized code/email",
					repo.lastLookupCode, repo.lastLookupEmail)
			}
			if repo.loginAuditCalls != 0 || repo.refreshStoreCalls != 0 {
				t.Fatalf("rejected login persisted success state: audit=%d refresh=%d", repo.loginAuditCalls, repo.refreshStoreCalls)
			}
		})
	}
}

func TestLoginSurfacesFailedLoginAuditError(t *testing.T) {
	auditErr := errors.New("audit storage unavailable")
	repo := &fakeRepository{findErr: repoData.ErrNotFound, failedLoginErr: auditErr}
	service := New(repo, security.NewTokenManager("test-secret-at-least-32-characters", time.Minute, time.Hour))

	_, err := service.Login(context.Background(), "acme", "missing@example.test", "password")
	if !errors.Is(err, auditErr) {
		t.Fatalf("Login() error = %v, want audit failure %v", err, auditErr)
	}
}

func TestLoginStoresRefreshAndAuditsSuccess(t *testing.T) {
	password := "correct-password"
	passwordHash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	repo := &fakeRepository{loginRecord: repoData.LoginRecord{
		TenantID: "tenant-id", TenantStatus: "active", UserID: "user-id",
		PasswordHash: string(passwordHash), MembershipStatus: "active",
	}}
	service := New(repo, security.NewTokenManager("test-secret-at-least-32-characters", time.Minute, time.Hour))

	pair, err := service.Login(context.Background(), "acme", "USER@example.test", password)
	if err != nil {
		t.Fatalf("Login() error = %v", err)
	}
	if pair.AccessToken == "" || pair.RefreshToken == "" {
		t.Fatal("Login() returned incomplete tokens")
	}
	if repo.refreshStoreCalls != 1 || repo.loginAuditCalls != 1 || repo.failedLoginCalls != 0 {
		t.Fatalf("unexpected persistence calls: refresh=%d success-audit=%d failure-audit=%d",
			repo.refreshStoreCalls, repo.loginAuditCalls, repo.failedLoginCalls)
	}
	if repo.lastLookupEmail != "user@example.test" {
		t.Fatalf("login lookup email = %q, want normalized email", repo.lastLookupEmail)
	}
}
