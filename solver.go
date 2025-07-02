package main

import (
	"cmp"
	"context"
	"fmt"
	"github.com/cert-manager/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
	acmeapisv1 "github.com/cert-manager/cert-manager/pkg/apis/acme/v1"
	acmev1 "github.com/cert-manager/cert-manager/pkg/client/clientset/versioned/typed/acme/v1"
	certmanagerv1 "github.com/cert-manager/cert-manager/pkg/client/clientset/versioned/typed/certmanager/v1"
	"github.com/go-acme/lego/v4/challenge"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/client-go/kubernetes"
	corev1 "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog/v2"
	"sync"
)

type providerKey struct {
	dnsName, key string
}

type LegoSolver struct {
	ctx context.Context

	corev1.SecretsGetter

	certmanagerv1.IssuersGetter
	certmanagerv1.ClusterIssuersGetter

	challengeStore cache.Store

	providers map[providerKey]challenge.Provider
	mux       sync.RWMutex
}

func (ls *LegoSolver) Name() string {
	return "lego-solver"
}

func (ls *LegoSolver) Present(ch *v1alpha1.ChallengeRequest) error {
	klog.InfoS(
		"Present",
		"ResolvedFQDN", ch.ResolvedFQDN,
		"Record", ch.Key,
	)

	keyAuthorization, token, err := ls.getKeyAuthorization(ch)
	if err != nil {
		return err
	}

	provider, err := ls.getProvider(ch)
	if err != nil {
		return err
	}

	return provider.Present(ch.ResolvedFQDN, token, keyAuthorization)
}

func (ls *LegoSolver) CleanUp(ch *v1alpha1.ChallengeRequest) error {
	klog.InfoS(
		"Cleanup",
		"ResolvedFQDN", ch.ResolvedFQDN,
		"Record", ch.Key,
	)

	keyAuthorization, token, err := ls.getKeyAuthorization(ch)
	if err != nil {
		return err
	}

	provider, err := ls.getProvider(ch)
	if err != nil {
		return err
	}

	return provider.CleanUp(ch.ResolvedFQDN, token, keyAuthorization)
}

func (ls *LegoSolver) Initialize(kubeClientConfig *rest.Config, stopCh <-chan struct{}) error {
	kc, err := kubernetes.NewForConfig(kubeClientConfig)
	if err != nil {
		return fmt.Errorf("failed to create kubernetes client: %w", err)
	}

	ls.SecretsGetter = kc.CoreV1()

	certmanagerV1Client, err := certmanagerv1.NewForConfig(kubeClientConfig)
	if err != nil {
		return fmt.Errorf("failed to create cert-manager client: %w", err)
	}

	ls.IssuersGetter = certmanagerV1Client
	ls.ClusterIssuersGetter = certmanagerV1Client

	acmeV1Interface, err := acmev1.NewForConfig(kubeClientConfig)
	if err != nil {
		return fmt.Errorf("failed to create acme client: %w", err)
	}

	challengelw := cache.NewListWatchFromClient(
		acmeV1Interface.RESTClient(),
		"challenges",
		metav1.NamespaceAll,
		fields.Everything(),
	)

	var ctrl cache.Controller

	ls.challengeStore, ctrl = cache.NewInformerWithOptions(cache.InformerOptions{
		ListerWatcher: challengelw,
		ObjectType:    &acmeapisv1.Challenge{},
		Handler: cache.ResourceEventHandlerFuncs{
			DeleteFunc: func(obj any) {
				ls.mux.Lock()
				defer ls.mux.Unlock()

				ch := obj.(*acmeapisv1.Challenge)
				delete(ls.providers, providerKey{dnsName: ch.Spec.DNSName, key: ch.Spec.Key})
			},
		},
		ResyncPeriod: 0,
		Indexers:     cache.Indexers{},
	})

	var cancel context.CancelFunc
	ls.ctx, cancel = context.WithCancel(context.Background())

	go func() {
		<-stopCh
		cancel()
	}()

	go ctrl.Run(ls.ctx.Done())

	ls.providers = make(map[providerKey]challenge.Provider)

	return nil
}

func (ls *LegoSolver) getProvider(ch *v1alpha1.ChallengeRequest) (provider challenge.Provider, err error) {
	pk := providerKey{dnsName: ch.DNSName, key: ch.Key}

	ls.mux.RLock()
	provider, ok := ls.providers[pk]

	if ok {
		ls.mux.RUnlock()
		return provider, nil
	}

	ls.mux.RUnlock()

	cfg, err := loadConfig(ch.Config)
	if err != nil {
		return nil, fmt.Errorf("failed to load config: %w", err)
	}

	var envs map[string]string
	if cfg.Envs != nil {
		envs = *cfg.Envs
	} else if cfg.EnvFrom != nil {
		ns := cmp.Or(cfg.EnvFrom.Secret.Namespace, ch.ResourceNamespace)

		envs, err = ls.getEnvsFromSecret(ns, cfg.EnvFrom.Secret.Name)
		if err != nil {
			return nil, fmt.Errorf("failed to get provider envs: %w", err)
		}
	}

	provider, err = newProvider(cfg.Provider, envs)
	if err != nil {
		return nil, fmt.Errorf("failed to create provider: %w", err)
	}

	ls.mux.Lock()
	defer ls.mux.Unlock()

	ls.providers[pk] = provider
	return provider, nil
}

func (ls *LegoSolver) getEnvsFromSecret(namespace, name string) (map[string]string, error) {
	secret, err := ls.Secrets(namespace).Get(ls.ctx, name, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to get secret: %w", err)
	}

	data := make(map[string]string, len(secret.Data))
	for key, bytes := range secret.Data {
		data[key] = string(bytes)
	}

	return data, nil
}
