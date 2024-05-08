package main

import (
	"context"
	"fmt"
	"github.com/cert-manager/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
	acmeapisv1 "github.com/cert-manager/cert-manager/pkg/apis/acme/v1"
	acmev1 "github.com/cert-manager/cert-manager/pkg/client/clientset/versioned/typed/acme/v1"
	certmanagerv1 "github.com/cert-manager/cert-manager/pkg/client/clientset/versioned/typed/certmanager/v1"
	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/challenge/dns01"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/client-go/kubernetes"
	corev1 "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog/v2"
	"sync"
)

type LegoSolver struct {
	corev1.CoreV1Interface
	certmanagerv1.CertmanagerV1Interface
	ctx context.Context

	challengeIndexer cache.Indexer
	providers        sync.Map
}

func (ls *LegoSolver) Name() string {
	return "lego-solver"
}

func (ls *LegoSolver) Present(ch *v1alpha1.ChallengeRequest) error {
	klog.InfoS(
		"Present txt record",
		"ResolvedFQDN", ch.ResolvedFQDN,
		"Record", ch.Key,
		"ResolvedZone", ch.ResolvedZone,
		"DNSName", ch.DNSName,
	)

	keyAuthorization, token, err := ls.getKeyAuthorization(ch.ResourceNamespace, ch.DNSName, ch.Key)
	if err != nil {
		return err
	}

	provider, err := ls.buildProvider(ch)
	if err != nil {
		return err
	}

	err = provider.Present(ch.DNSName, token, keyAuthorization)
	if err != nil {
		dns01.ClearFqdnCache()
		return err
	}

	ls.providers.Store(getChallengeKey(ch), provider)

	return nil
}

func (ls *LegoSolver) CleanUp(ch *v1alpha1.ChallengeRequest) error {
	klog.InfoS(
		"Cleanup txt record",
		"ResolvedFQDN", ch.ResolvedFQDN,
		"Record", ch.Key,
		"ResolvedZone", ch.ResolvedZone,
		"DNSName", ch.DNSName,
	)

	keyAuthorization, token, err := ls.getKeyAuthorization(ch.ResourceNamespace, ch.DNSName, ch.Key)
	if err != nil {
		return err
	}

	var provider challenge.Provider
	if v, ok := ls.providers.Load(getChallengeKey(ch)); ok {
		provider = v.(challenge.Provider)
	} else {
		provider, err = ls.buildProvider(ch)
		if err != nil {
			return err
		}
	}

	err = provider.CleanUp(ch.DNSName, token, keyAuthorization)
	if err != nil {
		dns01.ClearFqdnCache()
		return err
	}

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

	acmeV1Interface, err := acmev1.NewForConfig(kubeClientConfig)
	if err != nil {
		return fmt.Errorf("failed to create acme client: %w", err)
	}

	challengeWatcher := cache.NewListWatchFromClient(
		acmeV1Interface.RESTClient(),
		"challenges",
		metav1.NamespaceAll,
		fields.Everything(),
	)

	indexer, controller := cache.NewIndexerInformer(challengeWatcher, &acmeapisv1.Challenge{}, 0, cache.ResourceEventHandlerFuncs{
		DeleteFunc: func(obj interface{}) {
			ls.providers.Delete(getChallengeKey(obj))
		},
	}, cache.Indexers{})

	ls.challengeIndexer = indexer
	ls.ctx = context.Background()

	go func() {
		<-stopCh
		ls.ctx.Done()
	}()

	go controller.Run(ls.ctx.Done())

	return nil
}

func (ls *LegoSolver) buildProvider(ch *v1alpha1.ChallengeRequest) (provider challenge.Provider, err error) {
	cfg, err := loadConfig(ch.Config)
	if err != nil {
		return nil, fmt.Errorf("failed to load config: %w", err)
	}

	providerEnvs, err := ls.getProviderEnvs(cfg, ch.ResourceNamespace)
	if err != nil {
		return nil, fmt.Errorf("failed to get provider envs: %w", err)
	}

	return &LegoProvider{
		envs:     providerEnvs,
		provider: cfg.Provider,
	}, nil
}

func (ls *LegoSolver) getProviderEnvs(cfg *WebhookConfig, namespace string) (map[string]string, error) {
	if cfg.Envs != nil {
		return *cfg.Envs, nil
	}

	if cfg.EnvFrom == nil {
		return nil, nil
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

func getChallengeKey(v any) string {
	switch v.(type) {
	case *acmeapisv1.Challenge:
		ch := v.(*acmeapisv1.Challenge)
		return ch.Spec.DNSName + "." + ch.Spec.Key
	case *v1alpha1.ChallengeRequest:
		cr := v.(*v1alpha1.ChallengeRequest)
		return cr.DNSName + "." + cr.Key
	default:
		panic("getChallengeKey: unknown type")
	}
}
