package solver

import (
	"context"
	"testing"

	acmeapisv1 "github.com/cert-manager/cert-manager/pkg/apis/acme/v1"
	"github.com/go-acme/lego/v5/challenge"
	"k8s.io/client-go/tools/cache"
)

type fakeProvider struct{}

func (fakeProvider) Present(context.Context, string, string, string) error { return nil }
func (fakeProvider) CleanUp(context.Context, string, string, string) error { return nil }

var _ challenge.Provider = fakeProvider{}

func TestDeleteProviderForChallenge(t *testing.T) {
	t.Parallel()

	ls := &Solver{
		providers: map[providerKey]challenge.Provider{
			{dnsName: "example.com", key: "key"}: fakeProvider{},
		},
	}

	ls.deleteProviderForChallenge(&acmeapisv1.Challenge{
		Spec: acmeapisv1.ChallengeSpec{
			DNSName: "example.com",
			Key:     "key",
		},
	})

	if len(ls.providers) != 0 {
		t.Fatalf("expected provider cache to be empty, got %d entries", len(ls.providers))
	}
}

func TestDeleteProviderForChallengeTombstone(t *testing.T) {
	t.Parallel()

	ls := &Solver{
		providers: map[providerKey]challenge.Provider{
			{dnsName: "example.com", key: "key"}: fakeProvider{},
		},
	}

	ls.deleteProviderForChallenge(cache.DeletedFinalStateUnknown{
		Obj: &acmeapisv1.Challenge{
			Spec: acmeapisv1.ChallengeSpec{
				DNSName: "example.com",
				Key:     "key",
			},
		},
	})

	if len(ls.providers) != 0 {
		t.Fatalf("expected provider cache to be empty, got %d entries", len(ls.providers))
	}
}

func TestDeleteProviderForChallengeIgnoresUnknownObject(t *testing.T) {
	t.Parallel()

	ls := &Solver{
		providers: map[providerKey]challenge.Provider{
			{dnsName: "example.com", key: "key"}: fakeProvider{},
		},
	}

	ls.deleteProviderForChallenge("unexpected")

	if len(ls.providers) != 1 {
		t.Fatalf("expected provider cache to remain unchanged, got %d entries", len(ls.providers))
	}
}
