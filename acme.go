package main

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	acmev1 "github.com/cert-manager/cert-manager/pkg/apis/acme/v1"
	cmv1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmapisv1 "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	"github.com/go-jose/go-jose/v3"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/klog/v2"
)

func (solver *LegoSolver) getChallenge(dnsName, key string) *acmev1.Challenge {
	for _, obj := range solver.challengeIndexer.List() {
		ch, ok := obj.(*acmev1.Challenge)
		if !ok {
			continue
		}

		if ch.Spec.Type == acmev1.ACMEChallengeTypeDNS01 &&
			ch.Spec.DNSName == dnsName &&
			ch.Spec.Key == key {
			klog.InfoS("match challenge", "name", ch.Name, "namespace", ch.Namespace, "dnsName", dnsName)
			return ch
		}
	}

	return nil
}

func (solver *LegoSolver) getIssuerPrivKey(issuerRef cmapisv1.ObjectReference, namespace string) (crypto.PrivateKey, error) {
	var (
		secretName string
		key        string
	)

	switch issuerRef.Kind {
	case cmv1.ClusterIssuerKind:
		clusterIssuer, err := solver.cm.ClusterIssuers().Get(context.Background(), issuerRef.Name, metav1.GetOptions{})
		if err != nil {
			return nil, fmt.Errorf("get ClusterIssuer error: %w", err)
		}

		secretName = clusterIssuer.Spec.ACME.PrivateKey.Name
		key = clusterIssuer.Spec.ACME.PrivateKey.Key
		namespace = CertManagerNamespace
	case cmv1.IssuerKind:
		issuer, err := solver.cm.Issuers(namespace).Get(context.Background(), issuerRef.Name, metav1.GetOptions{})
		if err != nil {
			return nil, fmt.Errorf("get Issuer error: %w", err)
		}

		secretName = issuer.Spec.ACME.PrivateKey.Name
		key = issuer.Spec.ACME.PrivateKey.Key
	}

	if key == "" {
		key = "tls.key"
	}

	secret, err := solver.kc.CoreV1().Secrets(namespace).Get(context.Background(), secretName, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("get secret error: %w", err)
	}

	block, _ := pem.Decode(secret.Data[key])
	if block == nil {
		return nil, errors.New("failed to decode PEM block for issuer secret")
	}

	return x509.ParsePKCS1PrivateKey(block.Bytes)
}

func (solver *LegoSolver) getKeyAuthorization(namespace, dnsName, key string) (string, error) {
	ch := solver.getChallenge(dnsName, key)
	if ch == nil {
		return "", errors.New("no challenge match")
	}

	privKey, err := solver.getIssuerPrivKey(ch.Spec.IssuerRef, namespace)
	if err != nil {
		return "", fmt.Errorf("getIssuerPrivKey error: %w", err)
	}

	keyAuthorization, err := getKeyAuthorization(privKey, ch.Spec.Token)
	if err != nil {
		return "", fmt.Errorf("getKeyAuthorization error: %w", err)
	}

	keyAuthShaBytes := sha256.Sum256([]byte(keyAuthorization))
	value := base64.RawURLEncoding.EncodeToString(keyAuthShaBytes[:sha256.Size])

	if value != key {
		return "", errors.New("inconsistent keyAuthorization")
	}

	return keyAuthorization, nil
}

func getKeyAuthorization(privKey crypto.PrivateKey, token string) (string, error) {
	var publicKey crypto.PublicKey
	switch k := privKey.(type) {
	case *ecdsa.PrivateKey:
		publicKey = k.Public()
	case *rsa.PrivateKey:
		publicKey = k.Public()
	}

	// Generate the Key Authorization for the challenge
	jwk := &jose.JSONWebKey{Key: publicKey}

	thumbBytes, err := jwk.Thumbprint(crypto.SHA256)
	if err != nil {
		return "", err
	}

	// unpad the base64URL
	keyThumb := base64.RawURLEncoding.EncodeToString(thumbBytes)

	return token + "." + keyThumb, nil
}
