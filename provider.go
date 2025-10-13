package main

import (
	"os"
	"sync"

	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/go-acme/lego/v4/providers/dns"
)

var setenvMux sync.Mutex

type providerWrapper struct {
	provider challenge.Provider
	envs     map[string]string
}

func (lp *providerWrapper) Present(domain, token, keyAuth string) error {
	reset := setenvs(lp.envs)
	defer reset()

	if err := lp.provider.Present(domain, token, keyAuth); err != nil {
		dns01.ClearFqdnCache()
		return err
	}

	return nil
}

func (lp *providerWrapper) CleanUp(domain, token, keyAuth string) error {
	reset := setenvs(lp.envs)
	defer reset()

	if err := lp.provider.CleanUp(domain, token, keyAuth); err != nil {
		dns01.ClearFqdnCache()
		return err
	}

	return nil
}

func newProvider(provider string, envs map[string]string) (*providerWrapper, error) {
	reset := setenvs(envs)
	defer reset()

	p, err := dns.NewDNSChallengeProviderByName(provider)
	if err != nil {
		return nil, err
	}

	return &providerWrapper{p, envs}, nil
}

func setenvs(envs map[string]string) func() {
	if envs == nil {
		return func() {}
	}

	setenvMux.Lock()

	origEnvs := make(map[string]string, len(envs))
	for name, value := range envs {
		origEnvs[name] = os.Getenv(name)
		os.Setenv(name, value)
	}

	return func() {
		defer setenvMux.Unlock()
		for name, value := range origEnvs {
			if value == "" {
				os.Unsetenv(name)
			} else {
				os.Setenv(name, value)
			}
		}
	}
}
