package main

import (
	"context"
	"fmt"
	"github.com/cert-manager/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
	acmev1 "github.com/cert-manager/cert-manager/pkg/client/clientset/versioned/typed/acme/v1"
	certmanagerv1 "github.com/cert-manager/cert-manager/pkg/client/clientset/versioned/typed/certmanager/v1"
	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/challenge/dns01"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	corev1 "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/rest"
	"k8s.io/klog/v2"
	"strings"
)

type LegoSolver struct {
	corev1.CoreV1Interface
	certmanagerv1.CertmanagerV1Interface
	acmev1.AcmeV1Interface
	ctx context.Context
}

func (ls *LegoSolver) Name() string {
	return "lego-solver"
}

func (ls *LegoSolver) Present(ch *v1alpha1.ChallengeRequest) error {
	keyAuthorization, err := ls.getKeyAuthorization(ch.ResourceNamespace, ch.DNSName, ch.Key)
	if err != nil {
		return err
	}

	provider, err := ls.getProvider(ch)
	if err != nil {
		return err
	}

	err = provider.Present(getDomain(ch.ResolvedFQDN), "", keyAuthorization)
	if err != nil {
		dns01.ClearFqdnCache()
		return err
	}

	klog.InfoS(
		"Present",
		"ResolvedFQDN", ch.ResolvedFQDN,
		"Record", ch.Key,
	)

	return nil
}

func (ls *LegoSolver) CleanUp(ch *v1alpha1.ChallengeRequest) error {
	keyAuthorization, err := ls.getKeyAuthorization(ch.ResourceNamespace, ch.DNSName, ch.Key)
	if err != nil {
		return err
	}

	provider, err := ls.getProvider(ch)
	if err != nil {
		return err
	}

	err = provider.CleanUp(getDomain(ch.ResolvedFQDN), "", keyAuthorization)
	if err != nil {
		dns01.ClearFqdnCache()
		return err
	}

	klog.InfoS(
		"CleanUp",
		"ResolvedFQDN", ch.ResolvedFQDN,
		"Record", ch.Key,
	)

	return nil
}

func (ls *LegoSolver) Initialize(kubeClientConfig *rest.Config, stopCh <-chan struct{}) error {
	kc, err := kubernetes.NewForConfig(kubeClientConfig)
	if err != nil {
		return fmt.Errorf("failed to create kubernetes client: %w", err)
	}

	ls.CoreV1Interface = kc.CoreV1()

	ls.CertmanagerV1Interface, err = certmanagerv1.NewForConfig(kubeClientConfig)
	if err != nil {
		return fmt.Errorf("failed to create cert-manager client: %w", err)
	}

	ls.AcmeV1Interface, err = acmev1.NewForConfig(kubeClientConfig)
	if err != nil {
		return fmt.Errorf("failed to create acme client: %w", err)
	}

	go func() {
		<-stopCh
		ls.ctx.Done()
	}()

	return nil
}

func (ls *LegoSolver) getProvider(ch *v1alpha1.ChallengeRequest) (provider challenge.Provider, err error) {
	cfg, err := loadConfig(ch.Config)
	if err != nil {
		return nil, fmt.Errorf("failed to load config: %w", err)
	}

	providerEnvs, err := ls.getProviderEnvs(cfg, ch.ResourceNamespace)
	if err != nil {
		return nil, fmt.Errorf("failed to get provider envs: %w", err)
	}

	return LegoProvider{
		envs:     providerEnvs,
		provider: cfg.Provider,
	}, nil
}

func (ls *LegoSolver) getProviderEnvs(cfg *WebhookConfig, namespace string) (map[string]string, error) {
	if cfg.Envs != nil {
		return *cfg.Envs, nil
	}

	secret, err := ls.Secrets(namespace).Get(ls.ctx, cfg.EnvFrom.Secret.Name, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to get secret: %w", err)
	}

	data := make(map[string]string, len(secret.Data))
	for key, bytes := range secret.Data {
		data[key] = string(bytes)
	}
	return data, nil
}

func getDomain(fqdn string) string {
	domain := strings.TrimPrefix(fqdn, "_acme-challenge.")
	return strings.TrimSuffix(domain, ".")
}
