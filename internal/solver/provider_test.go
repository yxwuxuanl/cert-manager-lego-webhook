package solver

import (
	"context"
	"testing"
)

type contextRecordingProvider struct {
	presentContext context.Context
	cleanUpContext context.Context
}

func (p *contextRecordingProvider) Present(ctx context.Context, _, _, _ string) error {
	p.presentContext = ctx
	return nil
}

func (p *contextRecordingProvider) CleanUp(ctx context.Context, _, _, _ string) error {
	p.cleanUpContext = ctx
	return nil
}

func TestProviderWrapperPassesContext(t *testing.T) {
	t.Parallel()

	ctx := context.WithValue(t.Context(), struct{}{}, "value")
	provider := &contextRecordingProvider{}
	wrapper := &providerWrapper{provider: provider}

	if err := wrapper.Present(ctx, "example.com", "token", "key-auth"); err != nil {
		t.Fatalf("present challenge: %v", err)
	}

	if provider.presentContext != ctx {
		t.Fatal("expected Present context to be forwarded")
	}

	if err := wrapper.CleanUp(ctx, "example.com", "token", "key-auth"); err != nil {
		t.Fatalf("clean up challenge: %v", err)
	}

	if provider.cleanUpContext != ctx {
		t.Fatal("expected CleanUp context to be forwarded")
	}
}
