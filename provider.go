package main

import (
	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/providers/dns"
	"os"
	"sync"
)

var legoMux sync.Mutex

type LegoProvider struct {
	challenge.Provider

	provider string
	envs     map[string]string
}

func (lp *LegoProvider) Present(domain, token, keyAuth string) error {
	return lp.Do(func(provider challenge.Provider) error {
		return provider.Present(domain, token, keyAuth)
	})
}

func (lp *LegoProvider) CleanUp(domain, token, keyAuth string) error {
	return lp.Do(func(provider challenge.Provider) error {
		return provider.CleanUp(domain, token, keyAuth)
	})
}

func (lp *LegoProvider) Do(fn func(challenge.Provider) error) error {
	legoMux.Lock()

	existsEnvs := make(map[string]string)

	for name, value := range lp.envs {
		if exists := os.Getenv(name); exists != "" {
			existsEnvs[name] = exists
		}
		os.Setenv(name, value)
	}

	defer func() {
		for name := range lp.envs {
			if exists, ok := existsEnvs[name]; ok {
				os.Setenv(name, exists)
			} else {
				os.Unsetenv(name)
			}
		}
		legoMux.Unlock()
	}()

	if lp.Provider != nil {
		return fn(lp.Provider)
	}

	provider, err := dns.NewDNSChallengeProviderByName(lp.provider)
	if err != nil {
		return err
	}

	lp.Provider = provider

	return fn(provider)
}
