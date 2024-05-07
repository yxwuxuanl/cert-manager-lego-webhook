package main

import (
	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/providers/dns"
	"os"
	"sync"
)

var legoMux sync.Mutex

type LegoProvider struct {
	provider string
	envs     map[string]string
}

func (lp LegoProvider) Present(domain, token, keyAuth string) error {
	return lp.Do(func(provider challenge.Provider) error {
		return provider.Present(domain, token, keyAuth)
	})
}

func (lp LegoProvider) CleanUp(domain, token, keyAuth string) error {
	return lp.Do(func(provider challenge.Provider) error {
		return provider.CleanUp(domain, token, keyAuth)
	})
}

func (lp LegoProvider) Do(fn func(challenge.Provider) error) error {
	provider, err := dns.NewDNSChallengeProviderByName(lp.provider)
	if err != nil {
		return err
	}

	legoMux.Lock()
	for name, value := range lp.envs {
		os.Setenv(name, value)
	}

	defer func() {
		for name := range lp.envs {
			os.Unsetenv(name)
		}
		legoMux.Unlock()
	}()

	return fn(provider)
}
