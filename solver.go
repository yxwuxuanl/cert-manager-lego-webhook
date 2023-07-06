package main

import (
	"context"
	"fmt"
	"github.com/cert-manager/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
	acmev1 "github.com/cert-manager/cert-manager/pkg/apis/acme/v1"
	acmeclientv1 "github.com/cert-manager/cert-manager/pkg/client/clientset/versioned/typed/acme/v1"
	cmclientv1 "github.com/cert-manager/cert-manager/pkg/client/clientset/versioned/typed/certmanager/v1"
	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/go-acme/lego/v4/providers/dns"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog/v2"
	"os"
	"strings"
	"sync"
)

type LegoSolver struct {
	mux              sync.Mutex
	kc               kubernetes.Interface
	cm               cmclientv1.CertmanagerV1Interface
	challengeIndexer cache.Indexer
}

func (solver *LegoSolver) Name() string {
	return "lego-solver"
}

func (solver *LegoSolver) Present(ch *v1alpha1.ChallengeRequest) error {
	keyAuthorization, err := solver.getKeyAuthorization(ch.ResourceNamespace, ch.DNSName, ch.Key)
	if err != nil {
		klog.ErrorS(err, "getKeyAuthorization error", "ResolvedFQDN", ch.ResolvedFQDN)
		return err
	}

	provider, done, err := solver.getProvider(ch)
	if err != nil {
		klog.ErrorS(err, "getProvider error", "ResolvedFQDN", ch.ResolvedFQDN)
		return fmt.Errorf("getProvider error: %w", err)
	}

	defer done()

	err = provider.Present(getDomain(ch.ResolvedFQDN), "", keyAuthorization)
	if err != nil {
		dns01.ClearFqdnCache()
		klog.ErrorS(err, "Present error", "ResolvedFQDN", ch.ResolvedFQDN, "provider", fmt.Sprintf("%T", provider))
		return err
	}

	klog.InfoS("Present done", "ResolvedFQDN", ch.ResolvedFQDN, "provider", fmt.Sprintf("%T", provider))

	return nil
}

func (solver *LegoSolver) CleanUp(ch *v1alpha1.ChallengeRequest) error {
	keyAuthorization, err := solver.getKeyAuthorization(ch.ResourceNamespace, ch.DNSName, ch.Key)
	if err != nil {
		klog.ErrorS(err, "getKeyAuthorization error", "ResolvedFQDN", ch.ResolvedFQDN)
		return err
	}

	provider, done, err := solver.getProvider(ch)
	if err != nil {
		klog.ErrorS(err, "getProvider error", "ResolvedFQDN", ch.ResolvedFQDN)
		return fmt.Errorf("getProvider error: %w", err)
	}

	defer done()

	err = provider.CleanUp(getDomain(ch.ResolvedFQDN), "", keyAuthorization)
	if err != nil {
		dns01.ClearFqdnCache()
		klog.ErrorS(err, "CleanUp error", "ResolvedFQDN", ch.ResolvedFQDN, "provider", fmt.Sprintf("%T", provider))
		return err
	}

	klog.InfoS("CleanUp done", "ResolvedFQDN", ch.ResolvedFQDN, "provider", fmt.Sprintf("%T", provider))

	return nil
}

func (solver *LegoSolver) Initialize(kubeClientConfig *rest.Config, stopCh <-chan struct{}) (err error) {
	solver.kc, err = kubernetes.NewForConfig(kubeClientConfig)
	if err != nil {
		return err
	}

	solver.cm, err = cmclientv1.NewForConfig(kubeClientConfig)
	if err != nil {
		return err
	}

	acmeV1Client, err := acmeclientv1.NewForConfig(kubeClientConfig)
	if err != nil {
		return err
	}

	listWatcher := cache.NewListWatchFromClient(acmeV1Client.RESTClient(), "challenges", corev1.NamespaceAll, fields.Everything())
	indexer, watcher := cache.NewIndexerInformer(listWatcher, &acmev1.Challenge{}, 0, cache.ResourceEventHandlerFuncs{}, cache.Indexers{})
	solver.challengeIndexer = indexer

	go watcher.Run(stopCh)

	return
}

func (solver *LegoSolver) getProviderEnvs(cfg *WebhookConfig, namespace string) (map[string]string, error) {
	if cfg.Envs != nil {
		return cfg.Envs, nil
	}

	if cfg.EnvFrom != nil {
		if se := cfg.EnvFrom.Secret; se.Name != "" {
			return solver.getSecretEnv(se, namespace)
		}
	}

	return map[string]string{}, nil
}

func (solver *LegoSolver) getSecretEnv(se SecretEnv, namespace string) (map[string]string, error) {
	if se.Namespace != "" {
		namespace = se.Namespace
	}

	secret, err := solver.kc.CoreV1().Secrets(namespace).Get(context.Background(), se.Name, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}

	data := make(map[string]string)
	for key, bytes := range secret.Data {
		data[key] = string(bytes)
	}

	return data, err
}

func (solver *LegoSolver) getProvider(ch *v1alpha1.ChallengeRequest) (provider challenge.Provider, done func(), err error) {
	cfg, err := loadConfig(ch.Config)
	if err != nil {
		return nil, nil, fmt.Errorf("loadConfig error: %w", err)
	}

	if cfg.Provider == "" {
		return nil, nil, fmt.Errorf("no provider specified")
	}

	providerEnvs, err := solver.getProviderEnvs(cfg, ch.ResourceNamespace)
	if err != nil {
		return nil, nil, fmt.Errorf("getProviderEnvs error: %w", err)
	}

	var envs []string

	setenv := func(key, value string) error {
		if os.Getenv(key) != "" {
			return fmt.Errorf("environment variable conflict: %s", key)
		}
		os.Setenv(key, value)
		envs = append(envs, key)
		return nil
	}

	solver.mux.Lock()
	done = func() {
		for _, env := range envs {
			os.Unsetenv(env)
		}
		solver.mux.Unlock()
	}

	for key, value := range providerEnvs {
		if err = setenv(key, value); err != nil {
			done()
			return nil, nil, err
		}
	}

	provider, err = dns.NewDNSChallengeProviderByName(cfg.Provider)
	if err != nil {
		done()
		return nil, nil, err
	}

	return provider, done, nil
}

func getDomain(fqdn string) string {
	domain := strings.TrimPrefix(fqdn, "_acme-challenge.")
	return strings.TrimSuffix(domain, ".")
}
