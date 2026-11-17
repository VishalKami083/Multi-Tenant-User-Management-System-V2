package membership

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/vishalKami083/multitenant-usermgmt/internal/domain/shared"
)

type fakeRepository struct {
	called bool
}

func (r *fakeRepository) AddMembership(context.Context, string, string, string) error {
	return nil
}

func (r *fakeRepository) UpdateMembershipStatus(context.Context, string, string, string, string) error {
	r.called = true
	return nil
}

func TestCannotSuspendOwnMembership(t *testing.T) {
	repo := &fakeRepository{}
	svc := New(repo)

	err := svc.Update(context.Background(), shared.Identity{TenantID: "tenant", UserID: "user"}, "user", Update{Status: "suspended"})

	var appErr *shared.Error
	if !errors.As(err, &appErr) || appErr.Status != http.StatusBadRequest {
		t.Fatalf("self-suspension error = %v, want validation error", err)
	}
	if repo.called {
		t.Fatal("repository should not be called for self-suspension")
	}
}
